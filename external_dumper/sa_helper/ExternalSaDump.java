import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import sun.jvm.hotspot.HotSpotAgent;
import sun.jvm.hotspot.classfile.ClassLoaderDataGraph;
import sun.jvm.hotspot.oops.Field;
import sun.jvm.hotspot.oops.InstanceKlass;
import sun.jvm.hotspot.oops.Klass;
import sun.jvm.hotspot.oops.Method;
import sun.jvm.hotspot.runtime.VM;

public class ExternalSaDump {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: ExternalSaDump <pid>");
            System.exit(2);
        }

        int pid = Integer.parseInt(args[0]);
        HotSpotAgent agent = new HotSpotAgent();
        try {
            agent.attach(pid);

            final List<InstanceKlass> sorted = new ArrayList<InstanceKlass>();
            VM.getVM().getClassLoaderDataGraph().classesDo(new ClassLoaderDataGraph.ClassVisitor() {
                @Override
                public void visit(Klass klass) {
                    if (klass instanceof InstanceKlass) {
                        sorted.add((InstanceKlass) klass);
                    }
                }
            });
            sorted.sort(new Comparator<InstanceKlass>() {
                @Override
                public int compare(InstanceKlass left, InstanceKlass right) {
                    return safe(left.getName().asString()).compareTo(safe(right.getName().asString()));
                }
            });

            for (InstanceKlass klass : sorted) {
                dumpClass(klass);
            }
        } finally {
            try {
                agent.detach();
            } catch (Throwable ignored) {
            }
        }
    }

    private static void dumpClass(InstanceKlass klass) {
        String className = slashToDot(safe(klass.getName().asString()));
        System.out.println("Class: " + className);
        System.out.println("  Methods:");
        List<Method> methods = klass.getImmediateMethods();
        if (methods == null || methods.isEmpty()) {
            System.out.println("    <none>");
        } else {
            for (Method method : methods) {
                String name = safe(method.getName().asString());
                String signature = safe(method.getSignature().asString());
                System.out.println("    " + name + signature);
            }
        }

        System.out.println("  Fields:");
        List<Field> fields = klass.getImmediateFields();
        if (fields == null || fields.isEmpty()) {
            System.out.println("    <none>");
        } else {
            for (Field field : fields) {
                String name = safe(field.getName().asString());
                String signature = safe(field.getSignature().asString());
                System.out.println("    " + name + " : " + signature);
            }
        }
        System.out.println();
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }

    private static String slashToDot(String value) {
        return value.replace('/', '.').replace("+0x", ".0x").replace("/0x", ".0x");
    }
}
