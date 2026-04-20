#include <windows.h>
#include <rpc.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "jni.h"
#include "jvmti.h"

#pragma comment(lib, "Rpcrt4.lib")

#ifndef TARGET_JAVA_VERSION
#define TARGET_JAVA_VERSION 17
#endif

#if TARGET_JAVA_VERSION <= 8
#define AGENT_JVMTI_VERSION JVMTI_VERSION_1_1
#else
#define AGENT_JVMTI_VERSION JVMTI_VERSION_1_2
#endif

namespace {

using GetCreatedJavaVMsFn = jint(JNICALL *)(JavaVM **, jsize, jsize *);

constexpr jint ACC_PUBLIC = 0x0001;
constexpr jint ACC_PRIVATE = 0x0002;
constexpr jint ACC_PROTECTED = 0x0004;
constexpr jint ACC_STATIC = 0x0008;
constexpr jint ACC_FINAL = 0x0010;
constexpr jint ACC_SYNCHRONIZED = 0x0020;
constexpr jint ACC_VOLATILE = 0x0040;
constexpr jint ACC_TRANSIENT = 0x0080;
constexpr jint ACC_NATIVE = 0x0100;
constexpr jint ACC_INTERFACE = 0x0200;
constexpr jint ACC_ABSTRACT = 0x0400;
constexpr jint ACC_STRICT = 0x0800;
constexpr jint ACC_SYNTHETIC = 0x1000;
constexpr jint ACC_ANNOTATION = 0x2000;
constexpr jint ACC_ENUM = 0x4000;
constexpr size_t SESSION_TEXT_CAP = 1024;

struct DumpSessionConfigNative {
    uint32_t protocol_version;
    uint32_t target_pid;
    uint32_t detected_java_major;
    uint32_t agent_flavor;
    uint32_t dump_profile;
    uint32_t transport_mode;
    uint32_t batch_size;
    uint32_t close_after_success;
    wchar_t session_id[SESSION_TEXT_CAP];
    wchar_t profile_output_dir[SESSION_TEXT_CAP];
    wchar_t rawdump_tmp_path[SESSION_TEXT_CAP];
    wchar_t rawdump_final_path[SESSION_TEXT_CAP];
    wchar_t status_json_path[SESSION_TEXT_CAP];
    wchar_t agent_log_path[SESSION_TEXT_CAP];
};

struct SessionConfig {
    uint32_t protocol_version = 4;
    uint32_t target_pid = 0;
    uint32_t detected_java_major = TARGET_JAVA_VERSION;
    bool close_after_success = false;
    std::string dump_profile = "extended";
    std::string transport_mode = "native_fallback";
    uint32_t batch_size = 64;
    std::string agent_flavor;
    std::string session_id;
    std::filesystem::path profile_output_dir;
    std::filesystem::path rawdump_tmp_path;
    std::filesystem::path rawdump_final_path;
    std::filesystem::path status_json_path;
    std::filesystem::path agent_log_path;
};

struct DumpCounters {
    uint32_t classes_enumerated = 0;
    uint32_t classes_dumped = 0;
    uint32_t classes_skipped_signature = 0;
    uint32_t classes_skipped_metadata = 0;
    uint32_t classes_skipped_provenance = 0;
    uint32_t classes_skipped_jni = 0;
};

struct ClassMetadata {
    std::string name;
    std::string package_name;
    std::string signature;
    std::string generic_signature;
    std::string source_file;
    std::string code_source_url;
    std::string resource_url;
    std::string loader;
    std::string loader_class;
    std::string module_name;
    std::string flags;
    std::string class_modifiers;
};

struct WorkerContext {
    HMODULE module = nullptr;
    SessionConfig session;
};

std::string agent_flavor_name() {
    return TARGET_JAVA_VERSION <= 8 ? "legacy_jvmti" : "modern_jvmti";
}

std::filesystem::path module_directory(HMODULE module) {
    wchar_t buffer[MAX_PATH];
    const DWORD len = GetModuleFileNameW(module, buffer, MAX_PATH);
    if (len == 0) {
        return std::filesystem::current_path();
    }
    return std::filesystem::path(buffer).parent_path();
}

void debug_log(const std::string &message) {
    OutputDebugStringA((message + "\n").c_str());
}

std::filesystem::path safe_u8path(const std::string &value) {
    if (value.empty()) {
        return {};
    }
    try {
        return std::filesystem::u8path(value);
    } catch (...) {
        return {};
    }
}

std::string trim_copy(const std::string &value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    }).base();
    if (first >= last) {
        return {};
    }
    return std::string(first, last);
}

std::string json_escape(const std::string &value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (const unsigned char ch : value) {
        switch (ch) {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (ch < 0x20) {
                    std::ostringstream oss;
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(ch);
                    out += oss.str();
                } else {
                    out.push_back(static_cast<char>(ch));
                }
                break;
        }
    }
    return out;
}

std::string guid_string() {
    UUID id{};
    if (UuidCreate(&id) != RPC_S_OK) {
        return "unknown-guid";
    }

    RPC_CSTR out = nullptr;
    if (UuidToStringA(&id, &out) != RPC_S_OK || out == nullptr) {
        return "unknown-guid";
    }

    std::string guid(reinterpret_cast<char *>(out));
    RpcStringFreeA(&out);
    std::transform(guid.begin(), guid.end(), guid.begin(), [](unsigned char c) {
        return static_cast<char>(::tolower(c));
    });
    return guid;
}

std::string utf16_to_utf8(const wchar_t *data, size_t len) {
    if (data == nullptr || len == 0) {
        return {};
    }

    const int required =
        WideCharToMultiByte(CP_UTF8, 0, data, static_cast<int>(len), nullptr, 0, nullptr, nullptr);
    if (required <= 0) {
        return {};
    }

    std::string out(required, '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8, 0, data, static_cast<int>(len), out.data(), required, nullptr, nullptr);
    if (written <= 0) {
        return {};
    }
    out.resize(static_cast<size_t>(written));
    return out;
}

std::string wide_field_to_utf8(const wchar_t *value, size_t cap) {
    size_t len = 0;
    while (len < cap && value[len] != L'\0') {
        ++len;
    }
    return utf16_to_utf8(value, len);
}

std::string jchar_to_utf8(const jchar *data, const jsize len) {
    return utf16_to_utf8(reinterpret_cast<const wchar_t *>(data), static_cast<size_t>(len));
}

void append_log(const SessionConfig &config, const std::string &message) {
    try {
        if (!config.agent_log_path.empty()) {
            std::filesystem::create_directories(config.agent_log_path.parent_path());
            std::ofstream out(config.agent_log_path, std::ios::app | std::ios::binary);
            if (out.is_open()) {
                SYSTEMTIME st{};
                GetLocalTime(&st);
                out << '[' << std::setw(2) << std::setfill('0') << st.wHour << ':'
                    << std::setw(2) << std::setfill('0') << st.wMinute << ':'
                    << std::setw(2) << std::setfill('0') << st.wSecond << "] " << message << "\n";
            }
        }
    } catch (...) {
    }
}

void write_atomic_text(const std::filesystem::path &path, const std::string &text) {
    try {
        std::filesystem::create_directories(path.parent_path());
        const auto tmp = path;
        const auto temp_path = tmp.string() + ".tmp";
        {
            std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
            if (!out.is_open()) {
                return;
            }
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
        }
        std::error_code remove_error;
        std::filesystem::remove(path, remove_error);
        std::error_code rename_error;
        std::filesystem::rename(temp_path, path, rename_error);
        if (rename_error) {
            std::error_code copy_error;
            std::filesystem::copy_file(temp_path, path,
                                       std::filesystem::copy_options::overwrite_existing, copy_error);
            std::filesystem::remove(temp_path, remove_error);
        }
    } catch (...) {
    }
}

void write_status_json(const SessionConfig &config, const std::string &phase,
                       const std::string &message, uint32_t last_error_code,
                       const DumpCounters &counters, const bool finished) {
    std::string completion = "pending";
    if (phase == "success") {
        completion = "success";
    } else if (phase == "partial_success") {
        completion = "partial_success";
    } else if (phase == "error") {
        completion = "error";
    }
    std::ostringstream json;
    json << "{\n";
    json << "  \"session_id\": \"" << json_escape(config.session_id) << "\",\n";
    json << "  \"phase\": \"" << json_escape(phase) << "\",\n";
    json << "  \"message\": \"" << json_escape(message) << "\",\n";
    json << "  \"target_pid\": " << config.target_pid << ",\n";
    json << "  \"detected_java_major\": " << config.detected_java_major << ",\n";
    json << "  \"agent_flavor\": \"" << json_escape(config.agent_flavor) << "\",\n";
    json << "  \"dump_profile\": \"" << json_escape(config.dump_profile) << "\",\n";
    json << "  \"transport_mode\": \"" << json_escape(config.transport_mode) << "\",\n";
    json << "  \"dump_completion\": \"" << json_escape(completion) << "\",\n";
    json << "  \"last_error_code\": " << last_error_code << ",\n";
    json << "  \"classes_enumerated\": " << counters.classes_enumerated << ",\n";
    json << "  \"classes_dumped\": " << counters.classes_dumped << ",\n";
    json << "  \"classes_skipped_signature\": " << counters.classes_skipped_signature << ",\n";
    json << "  \"classes_skipped_metadata\": " << counters.classes_skipped_metadata << ",\n";
    json << "  \"classes_skipped_provenance\": " << counters.classes_skipped_provenance << ",\n";
    json << "  \"classes_skipped_jni\": " << counters.classes_skipped_jni << ",\n";
    json << "  \"finished_at\": \"" << (finished ? json_escape(guid_string()) : "") << "\"\n";
    json << "}\n";
    write_atomic_text(config.status_json_path, json.str());
}

SessionConfig session_from_native(const DumpSessionConfigNative &native) {
    SessionConfig config;
    config.protocol_version = native.protocol_version == 0 ? 4 : native.protocol_version;
    config.target_pid = native.target_pid == 0 ? GetCurrentProcessId() : native.target_pid;
    config.detected_java_major =
        native.detected_java_major == 0 ? TARGET_JAVA_VERSION : native.detected_java_major;
    config.close_after_success = native.close_after_success != 0;
    config.agent_flavor = native.agent_flavor == 1 ? "legacy_jvmti" : agent_flavor_name();
    config.dump_profile = native.dump_profile == 1
                              ? "core"
                              : native.dump_profile == 3 ? "simple" : "extended";
    config.transport_mode = native.transport_mode == 1
                                ? "runtime_attach"
                                : native.transport_mode == 2 ? "external_attach" : "native_fallback";
    config.batch_size = native.batch_size == 0 ? 64 : native.batch_size;
    config.session_id = wide_field_to_utf8(native.session_id, SESSION_TEXT_CAP);
    config.profile_output_dir = safe_u8path(wide_field_to_utf8(native.profile_output_dir, SESSION_TEXT_CAP));
    config.rawdump_tmp_path = safe_u8path(wide_field_to_utf8(native.rawdump_tmp_path, SESSION_TEXT_CAP));
    config.rawdump_final_path = safe_u8path(wide_field_to_utf8(native.rawdump_final_path, SESSION_TEXT_CAP));
    config.status_json_path = safe_u8path(wide_field_to_utf8(native.status_json_path, SESSION_TEXT_CAP));
    config.agent_log_path = safe_u8path(wide_field_to_utf8(native.agent_log_path, SESSION_TEXT_CAP));
    if (config.session_id.empty()) {
        config.session_id = guid_string();
    }
    return config;
}

SessionConfig session_from_file(const char *options, HMODULE module) {
    SessionConfig config;
    config.target_pid = GetCurrentProcessId();
    config.detected_java_major = TARGET_JAVA_VERSION;
    config.agent_flavor = agent_flavor_name();
    config.dump_profile = "extended";
    config.transport_mode = "native_fallback";
    config.batch_size = 64;
    config.session_id = guid_string();

    if (options == nullptr || options[0] == '\0') {
        const auto dir = module_directory(module);
        config.profile_output_dir = dir;
        config.rawdump_tmp_path = dir / (config.session_id + ".rawdump.tmp");
        config.rawdump_final_path = dir / (config.session_id + ".rawdump");
        config.status_json_path = dir / "status.json";
        config.agent_log_path = dir / "agent.log";
        return config;
    }

    std::ifstream input(safe_u8path(options), std::ios::binary);
    if (!input.is_open()) {
        return config;
    }

    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(input, line)) {
        const auto trimmed = trim_copy(line);
        if (trimmed.empty()) {
            continue;
        }
        const auto pos = trimmed.find('=');
        if (pos == std::string::npos) {
            continue;
        }
        values[trim_copy(trimmed.substr(0, pos))] = trim_copy(trimmed.substr(pos + 1));
    }

    if (values.count("protocol_version") != 0) {
        config.protocol_version = static_cast<uint32_t>(std::strtoul(values["protocol_version"].c_str(), nullptr, 10));
    }
    if (values.count("target_pid") != 0) {
        config.target_pid = static_cast<uint32_t>(std::strtoul(values["target_pid"].c_str(), nullptr, 10));
    }
    if (values.count("detected_java_major") != 0) {
        config.detected_java_major = static_cast<uint32_t>(std::strtoul(values["detected_java_major"].c_str(), nullptr, 10));
    }
    if (values.count("agent_flavor") != 0) {
        config.agent_flavor = values["agent_flavor"];
    }
    if (values.count("dump_profile") != 0) {
        config.dump_profile = values["dump_profile"];
    }
    if (values.count("transport_mode") != 0) {
        config.transport_mode = values["transport_mode"];
    }
    if (values.count("batch_size") != 0) {
        config.batch_size = static_cast<uint32_t>(std::strtoul(values["batch_size"].c_str(), nullptr, 10));
    }
    if (values.count("close_after_success") != 0) {
        config.close_after_success = values["close_after_success"] == "1";
    }
    if (values.count("session_id") != 0) {
        config.session_id = values["session_id"];
    }
    if (values.count("profile_output_dir") != 0) {
        config.profile_output_dir = safe_u8path(values["profile_output_dir"]);
    }
    if (values.count("rawdump_tmp_path") != 0) {
        config.rawdump_tmp_path = safe_u8path(values["rawdump_tmp_path"]);
    }
    if (values.count("rawdump_final_path") != 0) {
        config.rawdump_final_path = safe_u8path(values["rawdump_final_path"]);
    }
    if (values.count("status_json_path") != 0) {
        config.status_json_path = safe_u8path(values["status_json_path"]);
    }
    if (values.count("agent_log_path") != 0) {
        config.agent_log_path = safe_u8path(values["agent_log_path"]);
    }

    if (config.session_id.empty()) {
        config.session_id = guid_string();
    }
    return config;
}

bool locate_vm(JavaVM **vm) {
    const HMODULE jvm_mod = GetModuleHandleW(L"jvm.dll");
    if (!jvm_mod) {
        return false;
    }

    const auto fn =
        reinterpret_cast<GetCreatedJavaVMsFn>(GetProcAddress(jvm_mod, "JNI_GetCreatedJavaVMs"));
    if (!fn) {
        return false;
    }

    JavaVM *buffer[1] = {nullptr};
    jsize count = 0;
    if (fn(buffer, 1, &count) != JNI_OK || count == 0) {
        return false;
    }

    *vm = buffer[0];
    return true;
}

void deallocate(jvmtiEnv *jvmti, unsigned char *ptr) {
    if (jvmti != nullptr && ptr != nullptr) {
        jvmti->Deallocate(ptr);
    }
}

bool clear_exception(JNIEnv *env) {
    if (!env->ExceptionCheck()) {
        return false;
    }
    env->ExceptionClear();
    return true;
}

std::string jstring_to_utf8(JNIEnv *env, jstring value) {
    if (value == nullptr) {
        return {};
    }

    const jsize len = env->GetStringLength(value);
    const jchar *chars = env->GetStringChars(value, nullptr);
    if (chars == nullptr) {
        clear_exception(env);
        return {};
    }

    std::string out = jchar_to_utf8(chars, len);
    env->ReleaseStringChars(value, chars);
    return out;
}

jmethodID find_method(JNIEnv *env, jclass klass, const char *name, const char *sig) {
    if (klass == nullptr) {
        return nullptr;
    }
    jmethodID method = env->GetMethodID(klass, name, sig);
    if (method == nullptr) {
        clear_exception(env);
    }
    return method;
}

std::string object_to_string(JNIEnv *env, jobject obj) {
    if (obj == nullptr) {
        return {};
    }

    jclass klass = env->GetObjectClass(obj);
    if (klass == nullptr) {
        clear_exception(env);
        return {};
    }

    const jmethodID to_string = find_method(env, klass, "toString", "()Ljava/lang/String;");
    std::string out;
    if (to_string != nullptr) {
        auto value = static_cast<jstring>(env->CallObjectMethod(obj, to_string));
        if (!clear_exception(env) && value != nullptr) {
            out = jstring_to_utf8(env, value);
            env->DeleteLocalRef(value);
        }
    }

    env->DeleteLocalRef(klass);
    return out;
}

std::string signature_to_class(const char *sig) {
    if (sig == nullptr || sig[0] == '\0') {
        return {};
    }

    std::string s(sig);
    if (!s.empty() && s[0] == 'L') {
        s = s.substr(1);
    }
    if (!s.empty() && s.back() == ';') {
        s.pop_back();
    }
    std::replace(s.begin(), s.end(), '/', '.');
    return s;
}

std::string class_to_resource_path(const std::string &class_name) {
    std::string out = class_name;
    std::replace(out.begin(), out.end(), '.', '/');
    out.append(".class");
    return out;
}

std::string package_from_class(const std::string &class_name) {
    const auto pos = class_name.rfind('.');
    if (pos == std::string::npos) {
        return {};
    }
    return class_name.substr(0, pos);
}

std::string class_name_of_object(JNIEnv *env, jobject obj) {
    if (obj == nullptr) {
        return {};
    }

    jobject klass_obj = env->GetObjectClass(obj);
    if (klass_obj == nullptr) {
        clear_exception(env);
        return {};
    }

    jclass class_cls = env->GetObjectClass(klass_obj);
    if (class_cls == nullptr) {
        clear_exception(env);
        env->DeleteLocalRef(klass_obj);
        return {};
    }

    const jmethodID get_name = find_method(env, class_cls, "getName", "()Ljava/lang/String;");
    std::string out;
    if (get_name != nullptr) {
        auto name = static_cast<jstring>(env->CallObjectMethod(klass_obj, get_name));
        if (!clear_exception(env) && name != nullptr) {
            out = jstring_to_utf8(env, name);
            env->DeleteLocalRef(name);
        }
    }

    env->DeleteLocalRef(class_cls);
    env->DeleteLocalRef(klass_obj);
    return out;
}

std::string call_class_string_method(JNIEnv *env, jclass target, const char *name, const char *sig) {
    if (target == nullptr) {
        return {};
    }

    jclass class_cls = env->GetObjectClass(target);
    if (class_cls == nullptr) {
        clear_exception(env);
        return {};
    }

    const jmethodID method = find_method(env, class_cls, name, sig);
    std::string out;
    if (method != nullptr) {
        auto value = static_cast<jstring>(env->CallObjectMethod(target, method));
        if (!clear_exception(env) && value != nullptr) {
            out = jstring_to_utf8(env, value);
            env->DeleteLocalRef(value);
        }
    }

    env->DeleteLocalRef(class_cls);
    return out;
}

bool call_class_bool_method(JNIEnv *env, jclass target, const char *name) {
    if (target == nullptr) {
        return false;
    }

    jclass class_cls = env->GetObjectClass(target);
    if (class_cls == nullptr) {
        clear_exception(env);
        return false;
    }

    const jmethodID method = find_method(env, class_cls, name, "()Z");
    bool result = false;
    if (method != nullptr) {
        result = env->CallBooleanMethod(target, method) == JNI_TRUE;
        clear_exception(env);
    }

    env->DeleteLocalRef(class_cls);
    return result;
}

std::string format_modifiers(jint modifiers, const bool for_method, const bool for_field) {
    std::vector<std::string> parts;
    if ((modifiers & ACC_PUBLIC) != 0) parts.emplace_back("public");
    if ((modifiers & ACC_PRIVATE) != 0) parts.emplace_back("private");
    if ((modifiers & ACC_PROTECTED) != 0) parts.emplace_back("protected");
    if ((modifiers & ACC_STATIC) != 0) parts.emplace_back("static");
    if ((modifiers & ACC_FINAL) != 0) parts.emplace_back("final");
    if (for_method && (modifiers & ACC_SYNCHRONIZED) != 0) parts.emplace_back("synchronized");
    if (for_field && (modifiers & ACC_VOLATILE) != 0) parts.emplace_back("volatile");
    if (for_field && (modifiers & ACC_TRANSIENT) != 0) parts.emplace_back("transient");
    if (for_method && (modifiers & ACC_NATIVE) != 0) parts.emplace_back("native");
    if ((modifiers & ACC_ABSTRACT) != 0) parts.emplace_back("abstract");
    if (for_method && (modifiers & ACC_STRICT) != 0) parts.emplace_back("strictfp");
    if ((modifiers & ACC_SYNTHETIC) != 0) parts.emplace_back("synthetic");
    if ((modifiers & ACC_INTERFACE) != 0) parts.emplace_back("interface");
    if ((modifiers & ACC_ANNOTATION) != 0) parts.emplace_back("annotation");
    if ((modifiers & ACC_ENUM) != 0) parts.emplace_back("enum");

    if (parts.empty()) {
        return "none";
    }

    std::ostringstream oss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) oss << ',';
        oss << parts[i];
    }
    return oss.str();
}

std::string format_class_flags(JNIEnv *env, jclass clazz) {
    std::vector<std::string> flags;
    if (call_class_bool_method(env, clazz, "isInterface")) flags.emplace_back("interface");
    if (call_class_bool_method(env, clazz, "isEnum")) flags.emplace_back("enum");
    if (call_class_bool_method(env, clazz, "isAnnotation")) flags.emplace_back("annotation");
    if (call_class_bool_method(env, clazz, "isAnonymousClass")) flags.emplace_back("anonymous");
    if (call_class_bool_method(env, clazz, "isLocalClass")) flags.emplace_back("local");
    if (call_class_bool_method(env, clazz, "isMemberClass")) flags.emplace_back("member");
    if (call_class_bool_method(env, clazz, "isSynthetic")) flags.emplace_back("synthetic");
    if (call_class_bool_method(env, clazz, "isArray")) flags.emplace_back("array");
    if (call_class_bool_method(env, clazz, "isPrimitive")) flags.emplace_back("primitive");

    if (flags.empty()) {
        return "none";
    }

    std::ostringstream oss;
    for (size_t i = 0; i < flags.size(); ++i) {
        if (i != 0) oss << ',';
        oss << flags[i];
    }
    return oss.str();
}

std::string get_code_source_url(JNIEnv *env, jclass clazz) {
    if (clazz == nullptr) {
        return {};
    }

    jclass class_cls = env->GetObjectClass(clazz);
    if (class_cls == nullptr) {
        clear_exception(env);
        return {};
    }

    const jmethodID get_pd =
        find_method(env, class_cls, "getProtectionDomain", "()Ljava/security/ProtectionDomain;");
    jobject protection_domain = nullptr;
    if (get_pd != nullptr) {
        protection_domain = env->CallObjectMethod(clazz, get_pd);
        if (clear_exception(env)) {
            protection_domain = nullptr;
        }
    }

    std::string out;
    if (protection_domain != nullptr) {
        jclass pd_cls = env->GetObjectClass(protection_domain);
        if (pd_cls != nullptr) {
            const jmethodID get_cs =
                find_method(env, pd_cls, "getCodeSource", "()Ljava/security/CodeSource;");
            jobject code_source = nullptr;
            if (get_cs != nullptr) {
                code_source = env->CallObjectMethod(protection_domain, get_cs);
                if (clear_exception(env)) {
                    code_source = nullptr;
                }
            }

            if (code_source != nullptr) {
                jclass cs_cls = env->GetObjectClass(code_source);
                if (cs_cls != nullptr) {
                    const jmethodID get_loc =
                        find_method(env, cs_cls, "getLocation", "()Ljava/net/URL;");
                    jobject location = nullptr;
                    if (get_loc != nullptr) {
                        location = env->CallObjectMethod(code_source, get_loc);
                        if (clear_exception(env)) {
                            location = nullptr;
                        }
                    }

                    if (location != nullptr) {
                        out = object_to_string(env, location);
                        env->DeleteLocalRef(location);
                    }
                    env->DeleteLocalRef(cs_cls);
                }
                env->DeleteLocalRef(code_source);
            }
            env->DeleteLocalRef(pd_cls);
        }
        env->DeleteLocalRef(protection_domain);
    }

    env->DeleteLocalRef(class_cls);
    return out;
}

std::string get_resource_url(JNIEnv *env, jclass clazz, const std::string &class_name) {
    if (clazz == nullptr || class_name.empty()) {
        return {};
    }

    jclass class_cls = env->GetObjectClass(clazz);
    if (class_cls == nullptr) {
        clear_exception(env);
        return {};
    }

    std::string resource_name = "/" + class_to_resource_path(class_name);
    jstring resource_value = env->NewStringUTF(resource_name.c_str());
    std::string out;
    const jmethodID get_resource =
        find_method(env, class_cls, "getResource", "(Ljava/lang/String;)Ljava/net/URL;");
    if (get_resource != nullptr && resource_value != nullptr) {
        jobject url = env->CallObjectMethod(clazz, get_resource, resource_value);
        if (!clear_exception(env) && url != nullptr) {
            out = object_to_string(env, url);
            env->DeleteLocalRef(url);
        }
    }

    if (resource_value != nullptr) {
        env->DeleteLocalRef(resource_value);
    }
    env->DeleteLocalRef(class_cls);
    return out;
}

std::pair<std::string, std::string> get_loader_details(JNIEnv *env, jclass clazz) {
    if (clazz == nullptr) {
        return {"", ""};
    }

    jclass class_cls = env->GetObjectClass(clazz);
    if (class_cls == nullptr) {
        clear_exception(env);
        return {"", ""};
    }

    const jmethodID get_loader =
        find_method(env, class_cls, "getClassLoader", "()Ljava/lang/ClassLoader;");
    std::pair<std::string, std::string> out{"bootstrap", "bootstrap"};
    if (get_loader != nullptr) {
        jobject loader = env->CallObjectMethod(clazz, get_loader);
        if (clear_exception(env)) {
            loader = nullptr;
        }
        if (loader != nullptr) {
            out.first = object_to_string(env, loader);
            out.second = class_name_of_object(env, loader);
            env->DeleteLocalRef(loader);
            if (out.first.empty()) {
                out.first = out.second;
            }
        }
    }

    env->DeleteLocalRef(class_cls);
    return out;
}

std::string get_module_name(JNIEnv *env, jclass clazz) {
    if (clazz == nullptr) {
        return {};
    }

    jclass class_cls = env->GetObjectClass(clazz);
    if (class_cls == nullptr) {
        clear_exception(env);
        return {};
    }

    const jmethodID get_module = find_method(env, class_cls, "getModule", "()Ljava/lang/Module;");
    std::string out;
    if (get_module != nullptr) {
        jobject module = env->CallObjectMethod(clazz, get_module);
        if (!clear_exception(env) && module != nullptr) {
            jclass module_cls = env->GetObjectClass(module);
            if (module_cls != nullptr) {
                const jmethodID get_name =
                    find_method(env, module_cls, "getName", "()Ljava/lang/String;");
                if (get_name != nullptr) {
                    auto name = static_cast<jstring>(env->CallObjectMethod(module, get_name));
                    if (!clear_exception(env) && name != nullptr) {
                        out = jstring_to_utf8(env, name);
                        env->DeleteLocalRef(name);
                    }
                }
                if (out.empty()) {
                    out = object_to_string(env, module);
                }
                env->DeleteLocalRef(module_cls);
            }
            env->DeleteLocalRef(module);
        }
    }

    env->DeleteLocalRef(class_cls);
    return out;
}

bool is_core_profile(const SessionConfig &config) {
    return config.dump_profile == "core" || config.dump_profile == "simple";
}

bool is_simple_profile(const SessionConfig &config) {
    return config.dump_profile == "simple";
}

ClassMetadata collect_metadata(JNIEnv *env, jvmtiEnv *jvmti, jclass clazz, const char *signature,
                               const char *generic_signature, const SessionConfig &config,
                               DumpCounters &counters) {
    ClassMetadata meta;
    meta.name = signature_to_class(signature);
    meta.package_name = package_from_class(meta.name);

    if (!is_simple_profile(config)) {
        meta.signature = signature != nullptr ? signature : "";
        meta.generic_signature = generic_signature != nullptr ? generic_signature : "";

        char *source_file = nullptr;
        if (jvmti->GetSourceFileName(clazz, &source_file) == JVMTI_ERROR_NONE && source_file != nullptr) {
            meta.source_file = source_file;
        } else {
            counters.classes_skipped_metadata += 1;
        }
        deallocate(jvmti, reinterpret_cast<unsigned char *>(source_file));

        meta.flags = format_class_flags(env, clazz);

        jint class_modifiers = 0;
        if (jvmti->GetClassModifiers(clazz, &class_modifiers) == JVMTI_ERROR_NONE) {
            meta.class_modifiers = format_modifiers(class_modifiers, false, false);
        } else {
            meta.class_modifiers = "unknown";
            counters.classes_skipped_metadata += 1;
        }
    }

    if (!is_core_profile(config)) {
        meta.code_source_url = get_code_source_url(env, clazz);
        if (clear_exception(env)) {
            counters.classes_skipped_provenance += 1;
            meta.code_source_url.clear();
        }
        meta.resource_url = get_resource_url(env, clazz, meta.name);
        if (clear_exception(env)) {
            counters.classes_skipped_provenance += 1;
            meta.resource_url.clear();
        }
        const auto loader = get_loader_details(env, clazz);
        meta.loader = loader.first;
        meta.loader_class = loader.second;
        meta.module_name = get_module_name(env, clazz);
        if (clear_exception(env)) {
            counters.classes_skipped_provenance += 1;
            meta.module_name.clear();
        }
    }

    return meta;
}

void write_value(std::ofstream &out, const char *key, const std::string &value) {
    out << key << ": " << (value.empty() ? "Unknown" : value) << "\n";
}

void write_class_block(JNIEnv *env, jvmtiEnv *jvmti, std::ofstream &out, jclass clazz,
                       const ClassMetadata &meta, const SessionConfig &config, DumpCounters &counters) {
    out << "@@CLASS\n";
    write_value(out, "Name", meta.name);
    if (!is_simple_profile(config)) {
        write_value(out, "Package", meta.package_name);
        write_value(out, "Signature", meta.signature);
        write_value(out, "GenericSignature", meta.generic_signature);
        write_value(out, "SourceFile", meta.source_file);
        write_value(out, "CodeSourceUrl", meta.code_source_url);
        write_value(out, "ResourceUrl", meta.resource_url);
        write_value(out, "Loader", meta.loader);
        write_value(out, "LoaderClass", meta.loader_class);
        write_value(out, "Module", meta.module_name);
        write_value(out, "Flags", meta.flags);
        write_value(out, "ClassModifiers", meta.class_modifiers);
    }

    jint method_count = 0;
    jmethodID *methods = nullptr;
    if (jvmti->GetClassMethods(clazz, &method_count, &methods) == JVMTI_ERROR_NONE && methods != nullptr) {
        out << "MethodCount: " << method_count << "\n";
        for (jint index = 0; index < method_count; ++index) {
            char *name = nullptr;
            char *method_sig = nullptr;
            char *generic_sig = nullptr;
            jint modifiers = 0;
            std::string modifier_text = "unknown";
            if (!is_simple_profile(config) &&
                jvmti->GetMethodModifiers(methods[index], &modifiers) == JVMTI_ERROR_NONE) {
                modifier_text = format_modifiers(modifiers, true, false);
            }
            if (jvmti->GetMethodName(methods[index], &name, &method_sig,
                                     is_simple_profile(config) ? nullptr : &generic_sig) ==
                JVMTI_ERROR_NONE) {
                if (is_simple_profile(config)) {
                    out << "Method: " << (name != nullptr ? name : "<unknown>")
                        << (method_sig != nullptr ? method_sig : "()") << "\n";
                } else {
                    out << "Method: " << modifier_text << " | "
                        << (name != nullptr ? name : "<unknown>")
                        << (method_sig != nullptr ? method_sig : "()")
                        << " | Generic=" << (generic_sig != nullptr ? generic_sig : "-") << "\n";
                }
            }
            deallocate(jvmti, reinterpret_cast<unsigned char *>(name));
            deallocate(jvmti, reinterpret_cast<unsigned char *>(method_sig));
            deallocate(jvmti, reinterpret_cast<unsigned char *>(generic_sig));
        }
        deallocate(jvmti, reinterpret_cast<unsigned char *>(methods));
    } else {
        counters.classes_skipped_metadata += 1;
        out << "MethodCount: 0\n";
    }

    jint field_count = 0;
    jfieldID *fields = nullptr;
    if (jvmti->GetClassFields(clazz, &field_count, &fields) == JVMTI_ERROR_NONE && fields != nullptr) {
        out << "FieldCount: " << field_count << "\n";
        for (jint index = 0; index < field_count; ++index) {
            char *name = nullptr;
            char *field_sig = nullptr;
            char *generic_sig = nullptr;
            jint modifiers = 0;
            std::string modifier_text = "unknown";
            if (!is_simple_profile(config) &&
                jvmti->GetFieldModifiers(clazz, fields[index], &modifiers) == JVMTI_ERROR_NONE) {
                modifier_text = format_modifiers(modifiers, false, true);
            }
            if (jvmti->GetFieldName(clazz, fields[index], &name, &field_sig,
                                    is_simple_profile(config) ? nullptr : &generic_sig) ==
                JVMTI_ERROR_NONE) {
                if (is_simple_profile(config)) {
                    out << "Field: " << (name != nullptr ? name : "<unknown>")
                        << " : " << (field_sig != nullptr ? field_sig : "-") << "\n";
                } else {
                    out << "Field: " << modifier_text << " | "
                        << (name != nullptr ? name : "<unknown>")
                        << " | Signature=" << (field_sig != nullptr ? field_sig : "-")
                        << " | Generic=" << (generic_sig != nullptr ? generic_sig : "-") << "\n";
                }
            }
            deallocate(jvmti, reinterpret_cast<unsigned char *>(name));
            deallocate(jvmti, reinterpret_cast<unsigned char *>(field_sig));
            deallocate(jvmti, reinterpret_cast<unsigned char *>(generic_sig));
        }
        deallocate(jvmti, reinterpret_cast<unsigned char *>(fields));
    } else {
        counters.classes_skipped_metadata += 1;
        out << "FieldCount: 0\n";
    }

    out << "@@END\n";
}

bool wait_for_vm_ready(JavaVM **vm_out, const SessionConfig &config) {
    DumpCounters counters;
    write_status_json(config, "attach_wait", "waiting for JavaVM", 0, counters, false);
    append_log(config, "waiting for JavaVM");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        if (locate_vm(vm_out)) {
            return true;
        }
        Sleep(200);
    }
    return false;
}

bool acquire_jvmti(JavaVM *vm, const SessionConfig &config, JNIEnv **env_out, jvmtiEnv **jvmti_out,
                   const bool detach_when_done) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        JNIEnv *env = nullptr;
        if (detach_when_done) {
            if (vm->AttachCurrentThread(reinterpret_cast<void **>(&env), nullptr) != JNI_OK) {
                Sleep(200);
                continue;
            }
        } else if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
            Sleep(200);
            continue;
        }

        jvmtiEnv *jvmti = nullptr;
        if (vm->GetEnv(reinterpret_cast<void **>(&jvmti), AGENT_JVMTI_VERSION) == JNI_OK && jvmti != nullptr) {
            *env_out = env;
            *jvmti_out = jvmti;
            return true;
        }

        if (detach_when_done) {
            vm->DetachCurrentThread();
        }
        Sleep(200);
    }

    append_log(config, "failed to acquire JVMTI environment");
    return false;
}

bool dump_classes(JNIEnv *env, jvmtiEnv *jvmti, const SessionConfig &config, DumpCounters &counters) {
    std::error_code create_error;
    std::filesystem::create_directories(config.rawdump_tmp_path.parent_path(), create_error);
    if (create_error) {
        append_log(config, "failed to create rawdump directory: " + create_error.message());
        write_status_json(config, "error", "failed to create rawdump directory", 0, counters, true);
        return false;
    }
    std::ofstream out(config.rawdump_tmp_path, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        append_log(config, "failed to open temporary rawdump");
        write_status_json(config, "error", "failed to open temporary rawdump", GetLastError(), counters, true);
        return false;
    }

    jvmtiCapabilities caps{};
    if (!is_simple_profile(config)) {
        caps.can_get_source_file_name = 1;
        caps.can_get_synthetic_attribute = 1;
    }
    jvmti->AddCapabilities(&caps);

    jint class_count = 0;
    jclass *classes = nullptr;
    if (jvmti->GetLoadedClasses(&class_count, &classes) != JVMTI_ERROR_NONE || classes == nullptr) {
        append_log(config, "GetLoadedClasses failed");
        write_status_json(config, "error", "GetLoadedClasses failed", 0, counters, true);
        return false;
    }

    counters.classes_enumerated = static_cast<uint32_t>(class_count);
    write_status_json(config, "enumerating", "loaded classes enumerated", 0, counters, false);

    out << "JLIVEF_DUMP_V4\n";
    out << "ProtocolVersion: " << config.protocol_version << "\n";
    out << "SessionId: " << config.session_id << "\n";
    out << "DumpProfile: " << config.dump_profile << "\n";
    out << "TransportMode: " << config.transport_mode << "\n";
    const auto completion_pos = out.tellp();
    out << "DumpCompletion: " << std::setw(16) << std::left << "pending" << "\n";
    out << "TargetPid: " << config.target_pid << "\n";
    out << "DetectedJavaMajor: " << config.detected_java_major << "\n";
    out << "TargetArch: " << (sizeof(void *) == 8 ? "x64" : "x86") << "\n";
    out << "AgentFlavor: " << config.agent_flavor << "\n";
    out << "ClassCount: " << class_count << "\n";
    out << "ClassesEnumerated: " << class_count << "\n";
    const auto dumped_pos = out.tellp();
    out << "ClassesDumped: " << std::right << std::setw(10) << std::setfill('0') << 0 << "\n";
    const auto skipped_pos = out.tellp();
    out << "ClassesSkipped: " << std::right << std::setw(10) << std::setfill('0') << 0 << "\n";
    out << std::setfill(' ');
    write_status_json(config, "writing", "writing metadata dump", 0, counters, false);

    const uint32_t flush_interval = config.batch_size == 0 ? 64 : config.batch_size;
    for (jint index = 0; index < class_count; ++index) {
        if (env->PushLocalFrame(32) != JNI_OK) {
            counters.classes_skipped_jni += 1;
            continue;
        }

        char *signature = nullptr;
        char *generic_signature = nullptr;
        if (jvmti->GetClassSignature(classes[index], &signature,
                                    is_simple_profile(config) ? nullptr : &generic_signature) != JVMTI_ERROR_NONE ||
            signature == nullptr) {
            counters.classes_skipped_signature += 1;
            deallocate(jvmti, reinterpret_cast<unsigned char *>(signature));
            deallocate(jvmti, reinterpret_cast<unsigned char *>(generic_signature));
            env->PopLocalFrame(nullptr);
            continue;
        }

        const ClassMetadata meta =
            collect_metadata(env, jvmti, classes[index], signature, generic_signature, config, counters);
        write_class_block(env, jvmti, out, classes[index], meta, config, counters);
        counters.classes_dumped += 1;

        deallocate(jvmti, reinterpret_cast<unsigned char *>(signature));
        deallocate(jvmti, reinterpret_cast<unsigned char *>(generic_signature));
        if ((index + 1) % flush_interval == 0) {
            out.flush();
            write_status_json(config, "writing", "writing metadata dump", 0, counters, false);
        }
        env->PopLocalFrame(nullptr);
    }

    deallocate(jvmti, reinterpret_cast<unsigned char *>(classes));
    const uint32_t skipped_total = counters.classes_skipped_signature + counters.classes_skipped_jni +
                                   counters.classes_skipped_provenance;
    const bool partial = config.dump_profile == "extended" &&
                         (counters.classes_skipped_provenance > 0 || counters.classes_skipped_jni > 0 ||
                          counters.classes_skipped_signature > 0);
    const std::string completion = partial ? "partial_success" : "success";

    out.seekp(dumped_pos + static_cast<std::streamoff>(std::string("ClassesDumped: ").size()));
    out << std::right << std::setw(10) << std::setfill('0') << counters.classes_dumped;
    out.seekp(skipped_pos + static_cast<std::streamoff>(std::string("ClassesSkipped: ").size()));
    out << std::right << std::setw(10) << std::setfill('0') << skipped_total;
    out.seekp(completion_pos + static_cast<std::streamoff>(std::string("DumpCompletion: ").size()));
    out << std::setw(16) << std::left << completion;
    out.flush();
    out.close();

    std::error_code remove_error;
    std::filesystem::remove(config.rawdump_final_path, remove_error);
    std::error_code rename_error;
    std::filesystem::rename(config.rawdump_tmp_path, config.rawdump_final_path, rename_error);
    if (rename_error) {
        append_log(config, "failed to finalize rawdump: " + rename_error.message());
        write_status_json(config, "error", "failed to finalize rawdump", 0, counters, true);
        return false;
    }

    append_log(config, "dump written to " + config.rawdump_final_path.string());
    write_status_json(config, partial ? "partial_success" : "success",
                      partial ? "metadata dump completed with partial provenance"
                              : "metadata dump completed",
                      0, counters, true);
    return true;
}

DWORD run_session(JavaVM *vm, const SessionConfig &config, const bool detach_when_done) {
    try {
        DumpCounters counters;
        JNIEnv *env = nullptr;
        jvmtiEnv *jvmti = nullptr;

        if (!acquire_jvmti(vm, config, &env, &jvmti, detach_when_done)) {
            write_status_json(config, "error", "failed to attach current thread or get JVMTI", 0, counters, true);
            return 2;
        }

        write_status_json(config, "vm_ready", "JVMTI environment acquired", 0, counters, false);
        const bool ok = dump_classes(env, jvmti, config, counters);
        if (detach_when_done) {
            vm->DetachCurrentThread();
        }
        return ok ? 0 : 3;
    } catch (const std::exception &ex) {
        DumpCounters counters;
        append_log(config, std::string("run_session exception: ") + ex.what());
        write_status_json(config, "error", "run_session exception", 0, counters, true);
        return 4;
    } catch (...) {
        DumpCounters counters;
        append_log(config, "run_session unknown exception");
        write_status_json(config, "error", "run_session unknown exception", 0, counters, true);
        return 5;
    }
}

DWORD WINAPI worker_thread(LPVOID param) {
    try {
        std::unique_ptr<WorkerContext> context(reinterpret_cast<WorkerContext *>(param));
        JavaVM *vm = nullptr;
        if (!wait_for_vm_ready(&vm, context->session)) {
            DumpCounters counters;
            append_log(context->session, "locate_vm timeout");
            write_status_json(context->session, "error", "locate_vm timeout", 0, counters, true);
            return 1;
        }
        return run_session(vm, context->session, true);
    } catch (const std::exception &ex) {
        debug_log(std::string("worker_thread exception: ") + ex.what());
        return 10;
    } catch (...) {
        debug_log("worker_thread unknown exception");
        return 11;
    }
}

}  // namespace

extern "C" {

JNIEXPORT DWORD WINAPI StartDumpSession(LPVOID param) {
    try {
        if (param == nullptr) {
            return 1;
        }

        const auto native = *reinterpret_cast<const DumpSessionConfigNative *>(param);
        HMODULE module = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&StartDumpSession), &module);

        auto context = std::make_unique<WorkerContext>();
        context->module = module;
        context->session = session_from_native(native);
        if (context->session.agent_flavor.empty()) {
            context->session.agent_flavor = agent_flavor_name();
        }
        if (context->session.target_pid == 0) {
            context->session.target_pid = GetCurrentProcessId();
        }

        DumpCounters counters;
        write_status_json(context->session, "loaded", "StartDumpSession invoked", 0, counters, false);
        append_log(context->session, "StartDumpSession invoked");

        HANDLE thread = CreateThread(nullptr, 0, worker_thread, context.get(), 0, nullptr);
        if (thread == nullptr) {
            write_status_json(context->session, "error", "failed to start worker thread", GetLastError(), counters, true);
            append_log(context->session, "failed to start worker thread");
            return 2;
        }

        context.release();
        CloseHandle(thread);
        return 0;
    } catch (const std::exception &ex) {
        debug_log(std::string("StartDumpSession exception: ") + ex.what());
        return 50;
    } catch (...) {
        debug_log("StartDumpSession unknown exception");
        return 51;
    }
}

JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM *vm, char *options, void *reserved) {
    UNREFERENCED_PARAMETER(reserved);
    try {
        HMODULE module = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&Agent_OnAttach), &module);
        SessionConfig session = session_from_file(options, module);
        DumpCounters counters;
        write_status_json(session, "loaded", "Agent_OnAttach invoked", 0, counters, false);
        append_log(session, "Agent_OnAttach invoked");
        return run_session(vm, session, false) == 0 ? JNI_OK : JNI_ERR;
    } catch (const std::exception &ex) {
        debug_log(std::string("Agent_OnAttach exception: ") + ex.what());
        return JNI_ERR;
    } catch (...) {
        debug_log("Agent_OnAttach unknown exception");
        return JNI_ERR;
    }
}

JNIEXPORT jint JNICALL Agent_OnLoad(JavaVM *vm, char *options, void *reserved) {
    UNREFERENCED_PARAMETER(reserved);
    try {
        HMODULE module = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCWSTR>(&Agent_OnLoad), &module);
        SessionConfig session = session_from_file(options, module);
        DumpCounters counters;
        write_status_json(session, "loaded", "Agent_OnLoad invoked", 0, counters, false);
        append_log(session, "Agent_OnLoad invoked");
        return run_session(vm, session, false) == 0 ? JNI_OK : JNI_ERR;
    } catch (const std::exception &ex) {
        debug_log(std::string("Agent_OnLoad exception: ") + ex.what());
        return JNI_ERR;
    } catch (...) {
        debug_log("Agent_OnLoad unknown exception");
        return JNI_ERR;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(lpReserved);
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}

}
