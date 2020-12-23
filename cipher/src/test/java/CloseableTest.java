import java.io.Closeable;
import java.io.IOException;

public class CloseableTest {
    public static void main(String[] args) {
        A a = new A();
    }

    static class A implements Closeable {

        @Override
        public void close() throws IOException {
            System.out.println("a.close");
        }
    }

    class B implements Closeable {

        @Override
        public void close() throws IOException {
            System.out.println("b.close");
        }
    }
}
