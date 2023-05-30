package vn.iotstar.Controller.admin;

import java.io.IOException;

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

		String username = StringEscapeUtils.escapeHtml4(request.getParameter("admin-username"));
		String password = StringEscapeUtils.escapeHtml4(request.getParameter("admin-password"));
		Admin admin = new Admin();
		admin.setName(request.getParameter("name"));
		Admin admin_check = adminservice.checkAdminLogin(username, password);
		try {
			if (admin_check != null) {
				HttpSession session = request.getSession();
				session.setAttribute("admin-username", username);
				session.setAttribute("admin-password", password);
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
