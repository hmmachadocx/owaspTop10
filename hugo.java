import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.Properties;

public class VulnerableServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        // === CWE-73: External Control of File Name or Path ===
        String rName = request.getParameter("reportName");

        // Vulnerability: User input is directly used to construct a file path, 
        // which allows the possibility of path traversal attacks.
        File rFile = new File("/usr/local/apfr/reports/" + rName);

        // Vulnerability: If the file exists, it will be deleted based on user input.
        // Attackers can delete arbitrary files if they manipulate the reportName parameter.
        if (rFile.exists()) {
            rFile.delete();
        }

        // === CWE-22: Path Traversal ===
        // Here, attackers could manipulate the "reportName" parameter to navigate outside of the intended directory,
        // e.g., using "../" sequences to access system files.

        // === CWE-312: Cleartext Storage of Sensitive Information ===
        FileInputStream fis = null;
        byte[] arr = new byte[1024];

        try {
            Properties cfg = new Properties();
            // Simulate loading of a configuration
            cfg.load(new FileInputStream("/usr/local/apfr/config.properties"));

            // Vulnerability: User-controlled input is used to load a sensitive file
            // without validating if the path or file is safe.
            fis = new FileInputStream(cfg.getProperty("sub") + ".txt");

            int amt = fis.read(arr);

            // Vulnerability: Output sensitive content to the response, exposing data in logs
            // or to users who shouldn't have access.
            response.setContentType("text/plain");
            PrintWriter out = response.getWriter();
            out.println(new String(arr, 0, amt));

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
    }
}
