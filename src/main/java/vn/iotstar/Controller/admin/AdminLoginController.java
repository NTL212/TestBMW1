package vn.iotstar.Controller.admin;

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import vn.iotstar.Entity.Admin;
import vn.iotstar.Service.IAdminService;
import vn.iotstar.Service.Impl.AdminServiceImpl;
import org.apache.commons.text.StringEscapeUtils;
@WebServlet(urlPatterns = { "/admin/login" })
public class AdminLoginController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IAdminService adminservice = new AdminServiceImpl();
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		RequestDispatcher dispatcher = this.getServletContext().getRequestDispatcher("/view/admin/login.jsp");
		dispatcher.forward(request, response);
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		response.setContentType("text/html");

		String username = request.getParameter("admin-username");
		String password = request.getParameter("admin-password");
		
		String filteredUsername = StringEscapeUtils.escapeHtml4(username);
		String encodedUsername = URLEncoder.encode(filteredUsername, "UTF-8");
		
		String filteredPassword = StringEscapeUtils.escapeHtml4(password);
		String encodedPassword = URLEncoder.encode(filteredPassword, "UTF-8");
		Admin admin = new Admin();		
		admin.setName(request.getParameter("name"));
		Admin admin_check = adminservice.checkAdminLogin(encodedUsername, encodedPassword);
		try {
			if (admin_check != null) {
				HttpSession session = request.getSession();
				session.setAttribute("admin-username", encodedUsername);
				session.setAttribute("admin-password", encodedPassword);
				response.sendRedirect(request.getContextPath() + "/admin/homepage");
			} else {
				request.setAttribute("errorMessage", "Tài khoản hoặc mật khẩu không chính xác !!!");
				RequestDispatcher rd = request.getRequestDispatcher("/view/admin/login.jsp");
				rd.forward(request, response);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
