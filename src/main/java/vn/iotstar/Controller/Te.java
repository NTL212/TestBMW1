package vn.iotstar.Controller;

import org.owasp.encoder.Encode;
import org.apache.commons.text.StringEscapeUtils;
import java.util.regex.Pattern;

public class Te {
    public static void main(String[] args) {
        // Chuỗi cần mã hóa
        String input = "<script>\\u0061lert(1)</script>";

        // Sử dụng Encoder từ thư viện OWASP Encoder
        String encodedOwasp = Encode.forHtml(input);
        System.out.println("Encoded (OWASP Encoder): " + encodedOwasp);

        // Sử dụng StringEscapeUtils từ thư viện Apache Commons Text
        String encodedApache = StringEscapeUtils.escapeHtml4(input);
        System.out.println("Encoded (Apache Commons): " + encodedApache);
        
     // Biểu thức chính quy để tìm kiếm các ký tự đặc biệt
        String specialCharacters = "[\\\\{}]";
        
        // Thực hiện thay thế các ký tự đặc biệt bằng rỗng
        String output = input.replaceAll(specialCharacters, "");
        System.out.println("Biểu thức chính quy Output: " + output);
    }
}