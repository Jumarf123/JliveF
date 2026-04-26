use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::io;
use std::mem::size_of;

use crate::external_dumper_new::win32::{LocalLibrary, ModuleInfo, ProcessHandle};

const FIELD_FLAG_INITIALIZED: u32 = 1 << 0;
const FIELD_FLAG_GENERIC: u32 = 1 << 2;
const FIELD_FLAG_CONTENDED: u32 = 1 << 4;
const JVM_CONSTANT_UTF8: u8 = 1;
const MAX_CLASS_CHAIN: usize = 2_000_000;
const MAX_CP_ENTRIES: usize = 65_536;
const MAX_FIELDINFO_BYTES: usize = 1_000_000;
const MAX_FIELDS_PER_CLASS: usize = 65_536;
const MAX_METHODS_PER_CLASS: usize = 65_536;
const MAX_SYMBOL_BYTES: usize = 16 * 1024;
const MAX_TABLE_ENTRIES: usize = 250_000;
const MAX_VM_STRING_BYTES: usize = 512;

#[derive(Debug)]
pub struct HotspotDumper {
    process: ProcessHandle,
    layout: Layout,
}

#[derive(Debug, Clone)]
pub struct ClassDump {
    pub name: String,
    pub methods: Vec<String>,
    pub fields: Vec<FieldDump>,
}

#[derive(Debug, Clone)]
pub struct FieldDump {
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug, Default)]
pub struct DumpReport {
    pub classes: Vec<ClassDump>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
struct Layout {
    cld_head_addr: usize,
    cld_next_off: usize,
    cld_klasses_off: usize,
    klass_name_off: usize,
    klass_next_link_off: usize,
    ik_constants_off: usize,
    field_layout: FieldLayout,
    ik_init_state_off: usize,
    ik_methods_off: usize,
    method_const_method_off: usize,
    const_method_name_index_off: usize,
    const_method_signature_index_off: usize,
    const_pool_tags_off: usize,
    const_pool_length_off: usize,
    const_pool_size: usize,
    symbol_length_off: usize,
    symbol_body_off: usize,
    array_length_off: usize,
    pointer_array_data_off: usize,
    byte_array_data_off: usize,
    loaded_state: u8,
}

#[derive(Debug, Clone, Copy)]
enum FieldLayout {
    Stream {
        fieldinfo_stream_off: usize,
    },
    Legacy {
        fields_off: usize,
        java_fields_count_off: usize,
        u2_array_data_off: usize,
        field_slots: usize,
    },
}

#[derive(Debug)]
struct Tables {
    fields: HashMap<String, HashMap<String, VmField>>,
    type_sizes: HashMap<String, usize>,
    int_constants: HashMap<String, i32>,
}

#[derive(Debug, Clone)]
struct VmField {
    is_static: bool,
    offset: usize,
    address: usize,
}

#[derive(Debug, Clone, Copy)]
struct Exports {
    vm_structs_var: usize,
    vm_struct_stride_var: usize,
    vm_types_var: usize,
    vm_type_stride_var: usize,
    vm_int_constants_var: usize,
    vm_int_stride_var: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VmStructEntryRaw {
    type_name: usize,
    field_name: usize,
    type_string: usize,
    is_static: i32,
    offset: u64,
    address: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VmTypeEntryRaw {
    type_name: usize,
    superclass_name: usize,
    is_oop_type: i32,
    is_integer_type: i32,
    is_unsigned: i32,
    size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VmIntConstantEntryRaw {
    name: usize,
    value: i32,
}

#[derive(Default)]
struct DumpState {
    symbol_cache: HashMap<usize, String>,
    cp_utf8_cache: HashMap<(usize, u16), String>,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct ParsedFieldInfo {
    name_index: u16,
    signature_index: u16,
}

#[derive(Debug)]
struct Unsigned5Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl HotspotDumper {
    pub fn attach(pid: u32) -> io::Result<Self> {
        let process = ProcessHandle::open(pid)?;
        let jvm_module = process.find_module("jvm.dll")?;
        let exports = resolve_exports(&jvm_module)?;
        let tables = read_tables(&process, exports)?;
        let layout = Layout::build(&tables, jvm_module)?;
        Ok(Self { process, layout })
    }

    pub fn dump(&self) -> io::Result<DumpReport> {
        let mut state = DumpState::default();
        let mut classes = Vec::new();
        let mut seen_clds = HashSet::new();

        let mut cld = self.process.read_ptr(self.layout.cld_head_addr)?;
        let mut cld_steps = 0usize;
        while cld != 0 {
            cld_steps += 1;
            if cld_steps > MAX_CLASS_CHAIN {
                state.warn("class loader data chain exceeded sane limit");
                break;
            }
            if !seen_clds.insert(cld) {
                state.warn(format!(
                    "detected loop in ClassLoaderData chain at 0x{cld:016X}"
                ));
                break;
            }

            self.collect_cld_classes(cld, &mut state, &mut classes);
            cld = match self
                .process
                .read_ptr(cld.wrapping_add(self.layout.cld_next_off))
            {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to read ClassLoaderData::_next at 0x{cld:016X}: {err}"
                    ));
                    break;
                }
            };
        }

        classes.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(DumpReport {
            classes,
            warnings: state.warnings,
        })
    }

    fn collect_cld_classes(
        &self,
        cld_addr: usize,
        state: &mut DumpState,
        classes: &mut Vec<ClassDump>,
    ) {
        let mut seen_klasses = HashSet::new();
        let mut klass = match self
            .process
            .read_ptr(cld_addr.wrapping_add(self.layout.cld_klasses_off))
        {
            Ok(value) => value,
            Err(err) => {
                state.warn(format!(
                    "failed to read ClassLoaderData::_klasses at 0x{cld_addr:016X}: {err}"
                ));
                return;
            }
        };

        let mut steps = 0usize;
        while klass != 0 {
            steps += 1;
            if steps > MAX_CLASS_CHAIN {
                state.warn(format!(
                    "klass chain for CLD 0x{cld_addr:016X} exceeded sane limit"
                ));
                break;
            }
            if !seen_klasses.insert(klass) {
                state.warn(format!(
                    "detected loop in klass chain for CLD 0x{cld_addr:016X} at 0x{klass:016X}"
                ));
                break;
            }

            match self.read_class_dump(klass, state) {
                Ok(Some(class_dump)) => classes.push(class_dump),
                Ok(None) => {}
                Err(err) => state.warn(format!("failed to decode class at 0x{klass:016X}: {err}")),
            }

            klass = match self
                .process
                .read_ptr(klass.wrapping_add(self.layout.klass_next_link_off))
            {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to read Klass::_next_link at 0x{klass:016X}: {err}"
                    ));
                    break;
                }
            };
        }
    }

    fn read_class_dump(
        &self,
        klass_addr: usize,
        state: &mut DumpState,
    ) -> io::Result<Option<ClassDump>> {
        let name_ptr = self
            .process
            .read_ptr(klass_addr.wrapping_add(self.layout.klass_name_off))?;
        let internal_name = self.read_symbol(name_ptr, state)?;
        if internal_name.starts_with('[') {
            return Ok(None);
        }

        let init_state: u8 = self
            .process
            .read_value(klass_addr.wrapping_add(self.layout.ik_init_state_off))?;
        if init_state < self.layout.loaded_state {
            return Ok(None);
        }

        let constants_ptr = self
            .process
            .read_ptr(klass_addr.wrapping_add(self.layout.ik_constants_off))?;
        let methods_ptr = self
            .process
            .read_ptr(klass_addr.wrapping_add(self.layout.ik_methods_off))?;
        let methods = match self.read_methods(constants_ptr, methods_ptr, state) {
            Ok(values) => values,
            Err(err) => {
                state.warn(format!(
                    "failed to decode methods for {internal_name} at 0x{klass_addr:016X}: {err}"
                ));
                Vec::new()
            }
        };
        let fields = match self.read_fields(klass_addr, constants_ptr, state) {
            Ok(values) => values,
            Err(err) => {
                state.warn(format!(
                    "failed to decode fields for {internal_name} at 0x{klass_addr:016X}: {err}"
                ));
                Vec::new()
            }
        };

        Ok(Some(ClassDump {
            name: internal_name.replace('/', "."),
            methods,
            fields,
        }))
    }

    fn read_methods(
        &self,
        cp_addr: usize,
        methods_array_addr: usize,
        state: &mut DumpState,
    ) -> io::Result<Vec<String>> {
        if cp_addr == 0 || methods_array_addr == 0 {
            return Ok(Vec::new());
        }

        let length = self.read_array_length(methods_array_addr)?;
        if length > MAX_METHODS_PER_CLASS {
            return Err(other(format!("method count {length} exceeds sane limit")));
        }

        let mut methods = Vec::with_capacity(length);
        for index in 0..length {
            let entry_addr = methods_array_addr
                .wrapping_add(self.layout.pointer_array_data_off)
                .wrapping_add(index * size_of::<usize>());
            let method_ptr = match self.process.read_ptr(entry_addr) {
                Ok(value) if value != 0 => value,
                Ok(_) => continue,
                Err(err) => {
                    state.warn(format!(
                        "failed to read method pointer {index} from 0x{methods_array_addr:016X}: {err}"
                    ));
                    continue;
                }
            };

            let const_method_ptr = match self
                .process
                .read_ptr(method_ptr.wrapping_add(self.layout.method_const_method_off))
            {
                Ok(value) if value != 0 => value,
                Ok(_) => continue,
                Err(err) => {
                    state.warn(format!(
                        "failed to read Method::_constMethod at 0x{method_ptr:016X}: {err}"
                    ));
                    continue;
                }
            };

            let name_index: u16 = match self
                .process
                .read_value(const_method_ptr.wrapping_add(self.layout.const_method_name_index_off))
            {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to read ConstMethod::_name_index at 0x{const_method_ptr:016X}: {err}"
                    ));
                    continue;
                }
            };
            let signature_index: u16 = match self.process.read_value(
                const_method_ptr.wrapping_add(self.layout.const_method_signature_index_off),
            ) {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to read ConstMethod::_signature_index at 0x{const_method_ptr:016X}: {err}"
                    ));
                    continue;
                }
            };

            let name = match self.resolve_cp_utf8(cp_addr, name_index, state) {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to resolve method name cp#{name_index} in 0x{cp_addr:016X}: {err}"
                    ));
                    continue;
                }
            };
            let signature = match self.resolve_cp_utf8(cp_addr, signature_index, state) {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to resolve method signature cp#{signature_index} in 0x{cp_addr:016X}: {err}"
                    ));
                    continue;
                }
            };

            methods.push(format!("{name}{signature}"));
        }

        Ok(methods)
    }

    fn read_fields(
        &self,
        klass_addr: usize,
        cp_addr: usize,
        state: &mut DumpState,
    ) -> io::Result<Vec<FieldDump>> {
        match self.layout.field_layout {
            FieldLayout::Stream {
                fieldinfo_stream_off,
            } => {
                let fieldinfo_addr = self
                    .process
                    .read_ptr(klass_addr.wrapping_add(fieldinfo_stream_off))?;
                self.read_fields_stream(cp_addr, fieldinfo_addr, state)
            }
            FieldLayout::Legacy {
                fields_off,
                java_fields_count_off,
                u2_array_data_off,
                field_slots,
            } => {
                let fields_addr = self.process.read_ptr(klass_addr.wrapping_add(fields_off))?;
                let java_fields_count: u16 = self
                    .process
                    .read_value(klass_addr.wrapping_add(java_fields_count_off))?;
                self.read_fields_legacy(
                    cp_addr,
                    fields_addr,
                    usize::from(java_fields_count),
                    u2_array_data_off,
                    field_slots,
                    state,
                )
            }
        }
    }

    fn read_fields_stream(
        &self,
        cp_addr: usize,
        fieldinfo_addr: usize,
        state: &mut DumpState,
    ) -> io::Result<Vec<FieldDump>> {
        if cp_addr == 0 || fieldinfo_addr == 0 {
            return Ok(Vec::new());
        }

        let byte_len = self.read_array_length(fieldinfo_addr)?;
        if byte_len == 0 {
            return Ok(Vec::new());
        }
        if byte_len > MAX_FIELDINFO_BYTES {
            return Err(other(format!(
                "fieldinfo stream size {byte_len} exceeds sane limit"
            )));
        }

        let data = self.process.read_bytes(
            fieldinfo_addr.wrapping_add(self.layout.byte_array_data_off),
            byte_len,
        )?;
        let mut reader = Unsigned5Reader::new(&data);
        let java_fields = reader.next_uint()? as usize;
        let _injected_fields = reader.next_uint()? as usize;
        if java_fields > MAX_FIELDS_PER_CLASS {
            return Err(other(format!(
                "field count {java_fields} exceeds sane limit"
            )));
        }

        let mut fields = Vec::with_capacity(java_fields);
        for index in 0..java_fields {
            let field = match reader.read_field_info() {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to decode field #{index} in stream 0x{fieldinfo_addr:016X}: {err}"
                    ));
                    break;
                }
            };

            let name = match self.resolve_cp_utf8(cp_addr, field.name_index, state) {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to resolve field name cp#{} in 0x{cp_addr:016X}: {err}",
                        field.name_index
                    ));
                    continue;
                }
            };
            let descriptor = match self.resolve_cp_utf8(cp_addr, field.signature_index, state) {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to resolve field signature cp#{} in 0x{cp_addr:016X}: {err}",
                        field.signature_index
                    ));
                    continue;
                }
            };

            fields.push(FieldDump { name, descriptor });
        }

        Ok(fields)
    }

    fn read_fields_legacy(
        &self,
        cp_addr: usize,
        fields_addr: usize,
        java_fields_count: usize,
        u2_array_data_off: usize,
        field_slots: usize,
        state: &mut DumpState,
    ) -> io::Result<Vec<FieldDump>> {
        if cp_addr == 0 || fields_addr == 0 || java_fields_count == 0 {
            return Ok(Vec::new());
        }
        if java_fields_count > MAX_FIELDS_PER_CLASS {
            return Err(other(format!(
                "field count {java_fields_count} exceeds sane limit"
            )));
        }

        let short_count = self.read_array_length(fields_addr)?;
        let needed_shorts = java_fields_count
            .checked_mul(field_slots)
            .ok_or_else(|| other("field slot count overflow"))?;
        if short_count < needed_shorts {
            return Err(other(format!(
                "legacy field array too short: have {short_count} u2 entries, need {needed_shorts}"
            )));
        }

        let raw_bytes = self.process.read_bytes(
            fields_addr.wrapping_add(u2_array_data_off),
            needed_shorts
                .checked_mul(size_of::<u16>())
                .ok_or_else(|| other("legacy field byte count overflow"))?,
        )?;
        let shorts: Vec<u16> = raw_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        let mut fields = Vec::with_capacity(java_fields_count);
        for index in 0..java_fields_count {
            let base = index * field_slots;
            let name_index = shorts[base + 1];
            let signature_index = shorts[base + 2];

            let name = match self.resolve_cp_utf8(cp_addr, name_index, state) {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to resolve legacy field name cp#{name_index} in 0x{cp_addr:016X}: {err}"
                    ));
                    continue;
                }
            };
            let descriptor = match self.resolve_cp_utf8(cp_addr, signature_index, state) {
                Ok(value) => value,
                Err(err) => {
                    state.warn(format!(
                        "failed to resolve legacy field signature cp#{signature_index} in 0x{cp_addr:016X}: {err}"
                    ));
                    continue;
                }
            };

            fields.push(FieldDump { name, descriptor });
        }

        Ok(fields)
    }

    fn read_symbol(&self, symbol_addr: usize, state: &mut DumpState) -> io::Result<String> {
        if symbol_addr == 0 {
            return Err(other("null Symbol*"));
        }
        if let Some(cached) = state.symbol_cache.get(&symbol_addr) {
            return Ok(cached.clone());
        }

        let length: u16 = self
            .process
            .read_value(symbol_addr.wrapping_add(self.layout.symbol_length_off))?;
        let length = usize::from(length);
        if length > MAX_SYMBOL_BYTES {
            return Err(other(format!(
                "symbol at 0x{symbol_addr:016X} has unreasonable length {length}"
            )));
        }

        let bytes = self.process.read_bytes(
            symbol_addr.wrapping_add(self.layout.symbol_body_off),
            length,
        )?;
        let value = String::from_utf8_lossy(&bytes).into_owned();
        state.symbol_cache.insert(symbol_addr, value.clone());
        Ok(value)
    }

    fn resolve_cp_utf8(
        &self,
        cp_addr: usize,
        index: u16,
        state: &mut DumpState,
    ) -> io::Result<String> {
        if index == 0 {
            return Err(other("constant pool index is zero"));
        }
        if let Some(cached) = state.cp_utf8_cache.get(&(cp_addr, index)) {
            return Ok(cached.clone());
        }

        let cp_len: i32 = self
            .process
            .read_value(cp_addr.wrapping_add(self.layout.const_pool_length_off))?;
        if cp_len <= 0 || cp_len as usize > MAX_CP_ENTRIES {
            return Err(other(format!(
                "constant pool at 0x{cp_addr:016X} has unreasonable length {cp_len}"
            )));
        }
        if usize::from(index) >= cp_len as usize {
            return Err(other(format!(
                "constant pool index {index} is out of bounds for length {cp_len}"
            )));
        }

        let tags_ptr = self
            .process
            .read_ptr(cp_addr.wrapping_add(self.layout.const_pool_tags_off))?;
        let tag: u8 = self.process.read_value(
            tags_ptr
                .wrapping_add(self.layout.byte_array_data_off)
                .wrapping_add(usize::from(index)),
        )?;
        if tag != JVM_CONSTANT_UTF8 {
            return Err(other(format!(
                "constant pool entry {index} in 0x{cp_addr:016X} is not Utf8 (tag={tag})"
            )));
        }

        let slot_addr = cp_addr
            .wrapping_add(self.layout.const_pool_size)
            .wrapping_add(usize::from(index) * size_of::<usize>());
        let symbol_ptr = self.process.read_ptr(slot_addr)?;
        let value = self.read_symbol(symbol_ptr, state)?;
        state.cp_utf8_cache.insert((cp_addr, index), value.clone());
        Ok(value)
    }

    fn read_array_length(&self, array_addr: usize) -> io::Result<usize> {
        let length: i32 = self
            .process
            .read_value(array_addr.wrapping_add(self.layout.array_length_off))?;
        if length < 0 {
            return Err(other(format!(
                "negative array length {length} at 0x{array_addr:016X}"
            )));
        }
        Ok(length as usize)
    }
}

impl DumpReport {
    pub fn render(&self) -> String {
        let mut output = String::new();
        for (class_index, class_dump) in self.classes.iter().enumerate() {
            if class_index != 0 {
                output.push('\n');
            }

            let _ = writeln!(output, "Class: {}", class_dump.name);
            let _ = writeln!(output, "  Methods:");
            for method in &class_dump.methods {
                let _ = writeln!(output, "    {method}");
            }
            let _ = writeln!(output, "  Fields:");
            for field in &class_dump.fields {
                let _ = writeln!(output, "    {} : {}", field.name, field.descriptor);
            }
        }
        output
    }
}

impl Layout {
    fn build(tables: &Tables, _jvm_module: ModuleInfo) -> io::Result<Self> {
        let array_length_off = tables.offset("Array<Klass*>", "_length")?;
        let pointer_array_data_off = tables.offset_any("Array<Klass*>", &["_data[0]", "_data"])?;
        let byte_array_data_off = tables
            .maybe_offset_any("Array<u1>", &["_data[0]", "_data"])
            .unwrap_or_else(|| align_up(array_length_off + size_of::<i32>(), 1));
        let symbol_body_off = tables
            .maybe_offset_any("Symbol", &["_body[0]", "_body"])
            .ok_or_else(|| other("missing VMStruct field Symbol::_body or Symbol::_body[0]"))?;
        let field_layout = if let Some(fieldinfo_stream_off) =
            tables.maybe_offset("InstanceKlass", "_fieldinfo_stream")
        {
            FieldLayout::Stream {
                fieldinfo_stream_off,
            }
        } else {
            let fields_off = tables.offset("InstanceKlass", "_fields")?;
            let java_fields_count_off = tables.offset("InstanceKlass", "_java_fields_count")?;
            let u2_array_data_off = tables
                .maybe_offset_any("Array<u2>", &["_data[0]", "_data"])
                .unwrap_or_else(|| align_up(array_length_off + size_of::<i32>(), size_of::<u16>()));
            let field_slots = tables
                .maybe_int_constant("FieldInfo::field_slots")
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(6);
            FieldLayout::Legacy {
                fields_off,
                java_fields_count_off,
                u2_array_data_off,
                field_slots,
            }
        };

        Ok(Self {
            cld_head_addr: tables.static_address("ClassLoaderDataGraph", "_head")?,
            cld_next_off: tables.offset("ClassLoaderData", "_next")?,
            cld_klasses_off: tables.offset("ClassLoaderData", "_klasses")?,
            klass_name_off: tables.offset("Klass", "_name")?,
            klass_next_link_off: tables.offset("Klass", "_next_link")?,
            ik_constants_off: tables.offset("InstanceKlass", "_constants")?,
            field_layout,
            ik_init_state_off: tables.offset("InstanceKlass", "_init_state")?,
            ik_methods_off: tables.offset("InstanceKlass", "_methods")?,
            method_const_method_off: tables.offset("Method", "_constMethod")?,
            const_method_name_index_off: tables.offset("ConstMethod", "_name_index")?,
            const_method_signature_index_off: tables.offset("ConstMethod", "_signature_index")?,
            const_pool_tags_off: tables.offset("ConstantPool", "_tags")?,
            const_pool_length_off: tables.offset("ConstantPool", "_length")?,
            const_pool_size: tables.type_size("ConstantPool")?,
            symbol_length_off: tables.offset("Symbol", "_length")?,
            symbol_body_off,
            array_length_off,
            pointer_array_data_off,
            byte_array_data_off,
            loaded_state: tables.int_constant("InstanceKlass::loaded")? as u8,
        })
    }
}

impl Tables {
    fn maybe_offset(&self, type_name: &str, field_name: &str) -> Option<usize> {
        let field = self.fields.get(type_name)?.get(field_name)?;
        if field.is_static {
            None
        } else {
            Some(field.offset)
        }
    }

    fn maybe_offset_any(&self, type_name: &str, field_names: &[&str]) -> Option<usize> {
        field_names
            .iter()
            .find_map(|field_name| self.maybe_offset(type_name, field_name))
    }

    fn offset(&self, type_name: &str, field_name: &str) -> io::Result<usize> {
        self.maybe_offset(type_name, field_name)
            .ok_or_else(|| other(format!("missing VMStruct field {type_name}::{field_name}")))
    }

    fn offset_any(&self, type_name: &str, field_names: &[&str]) -> io::Result<usize> {
        self.maybe_offset_any(type_name, field_names)
            .ok_or_else(|| {
                other(format!(
                    "missing VMStruct field {}::{}",
                    type_name,
                    field_names.join(" or ")
                ))
            })
    }

    fn static_address(&self, type_name: &str, field_name: &str) -> io::Result<usize> {
        let field = self
            .fields
            .get(type_name)
            .and_then(|fields| fields.get(field_name))
            .ok_or_else(|| other(format!("missing VMStruct field {type_name}::{field_name}")))?;
        if !field.is_static {
            return Err(other(format!(
                "VMStruct field {type_name}::{field_name} is not static"
            )));
        }
        Ok(field.address)
    }

    fn type_size(&self, type_name: &str) -> io::Result<usize> {
        self.type_sizes
            .get(type_name)
            .copied()
            .ok_or_else(|| other(format!("missing VMType size for {type_name}")))
    }

    fn int_constant(&self, name: &str) -> io::Result<i32> {
        self.int_constants
            .get(name)
            .copied()
            .ok_or_else(|| other(format!("missing VMIntConstant {name}")))
    }

    fn maybe_int_constant(&self, name: &str) -> Option<i32> {
        self.int_constants.get(name).copied()
    }
}

impl DumpState {
    fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }
}

impl<'a> Unsigned5Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn next_uint(&mut self) -> io::Result<u32> {
        const LG_H: u32 = 6;
        const H: u32 = 1 << LG_H;
        const X: u32 = 1;
        const MAX_B: u32 = 0xFF;
        const L: u32 = (MAX_B + 1) - X - H;
        const MAX_LENGTH: usize = 5;

        let pos = self.pos;
        let Some(&first) = self.bytes.get(pos) else {
            return Err(other("unexpected end of UNSIGNED5 stream"));
        };

        let b0 = u32::from(first);
        if b0 < X {
            return Err(other("encountered excluded UNSIGNED5 byte"));
        }

        let mut sum = b0 - X;
        if sum < L {
            self.pos = pos + 1;
            return Ok(sum);
        }

        let mut lg_hi = LG_H;
        for i in 1..MAX_LENGTH {
            let Some(&next) = self.bytes.get(pos + i) else {
                return Err(other("truncated UNSIGNED5 value"));
            };
            let bi = u32::from(next);
            if bi < X {
                return Err(other("encountered excluded UNSIGNED5 byte"));
            }
            sum = sum.wrapping_add((bi - X) << lg_hi);
            if bi < X + L || i == MAX_LENGTH - 1 {
                self.pos = pos + i + 1;
                return Ok(sum);
            }
            lg_hi += LG_H;
        }

        Err(other("invalid UNSIGNED5 sequence"))
    }

    fn read_field_info(&mut self) -> io::Result<ParsedFieldInfo> {
        let name_index = checked_u16(self.next_uint()?, "field name index")?;
        let signature_index = checked_u16(self.next_uint()?, "field signature index")?;
        let _offset = self.next_uint()?;
        let _access_flags = self.next_uint()?;
        let field_flags = self.next_uint()?;

        if field_flags & FIELD_FLAG_INITIALIZED != 0 {
            let _ = self.next_uint()?;
        }
        if field_flags & FIELD_FLAG_GENERIC != 0 {
            let _ = self.next_uint()?;
        }
        if field_flags & FIELD_FLAG_CONTENDED != 0 {
            let _ = self.next_uint()?;
        }

        Ok(ParsedFieldInfo {
            name_index,
            signature_index,
        })
    }
}

fn resolve_exports(module: &ModuleInfo) -> io::Result<Exports> {
    let local = LocalLibrary::map_exports_only(&module.path)?;
    Ok(Exports {
        vm_structs_var: module.base + local.export_rva("gHotSpotVMStructs")?,
        vm_struct_stride_var: module.base + local.export_rva("gHotSpotVMStructEntryArrayStride")?,
        vm_types_var: module.base + local.export_rva("gHotSpotVMTypes")?,
        vm_type_stride_var: module.base + local.export_rva("gHotSpotVMTypeEntryArrayStride")?,
        vm_int_constants_var: module.base + local.export_rva("gHotSpotVMIntConstants")?,
        vm_int_stride_var: module.base
            + local.export_rva("gHotSpotVMIntConstantEntryArrayStride")?,
    })
}

fn read_tables(process: &ProcessHandle, exports: Exports) -> io::Result<Tables> {
    let vm_structs_base = process.read_ptr(exports.vm_structs_var)?;
    let vm_struct_stride: u64 = process.read_value(exports.vm_struct_stride_var)?;
    let vm_types_base = process.read_ptr(exports.vm_types_var)?;
    let vm_type_stride: u64 = process.read_value(exports.vm_type_stride_var)?;
    let vm_int_base = process.read_ptr(exports.vm_int_constants_var)?;
    let vm_int_stride: u64 = process.read_value(exports.vm_int_stride_var)?;

    let mut fields: HashMap<String, HashMap<String, VmField>> = HashMap::new();
    for index in 0..MAX_TABLE_ENTRIES {
        let entry_addr = vm_structs_base.wrapping_add(index * vm_struct_stride as usize);
        let raw: VmStructEntryRaw = process.read_value(entry_addr)?;
        if raw.field_name == 0 {
            break;
        }
        let type_name = process.read_c_string(raw.type_name, MAX_VM_STRING_BYTES)?;
        let field_name = process.read_c_string(raw.field_name, MAX_VM_STRING_BYTES)?;
        fields.entry(type_name).or_default().insert(
            field_name,
            VmField {
                is_static: raw.is_static != 0,
                offset: raw.offset as usize,
                address: raw.address,
            },
        );
    }

    let mut type_sizes = HashMap::new();
    for index in 0..MAX_TABLE_ENTRIES {
        let entry_addr = vm_types_base.wrapping_add(index * vm_type_stride as usize);
        let raw: VmTypeEntryRaw = process.read_value(entry_addr)?;
        if raw.type_name == 0 {
            break;
        }
        let type_name = process.read_c_string(raw.type_name, MAX_VM_STRING_BYTES)?;
        type_sizes.insert(type_name, raw.size as usize);
    }

    let mut int_constants = HashMap::new();
    for index in 0..MAX_TABLE_ENTRIES {
        let entry_addr = vm_int_base.wrapping_add(index * vm_int_stride as usize);
        let raw: VmIntConstantEntryRaw = process.read_value(entry_addr)?;
        if raw.name == 0 {
            break;
        }
        let name = process.read_c_string(raw.name, MAX_VM_STRING_BYTES)?;
        int_constants.insert(name, raw.value);
    }

    Ok(Tables {
        fields,
        type_sizes,
        int_constants,
    })
}

fn align_up(value: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        value
    } else {
        (value + (alignment - 1)) & !(alignment - 1)
    }
}

fn checked_u16(value: u32, what: &str) -> io::Result<u16> {
    u16::try_from(value).map_err(|_| other(format!("{what} is out of range: {value}")))
}

fn other(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message.into())
}
