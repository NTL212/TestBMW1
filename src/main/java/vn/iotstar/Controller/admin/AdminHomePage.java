package vn.iotstar.Controller.admin;

import java.io.IOException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Entity.Admin;
import vn.iotstar.Service.IAdminService;
import vn.iotstar.Service.Impl.AdminServiceImpl;
@WebServlet(urlPatterns = { "/admin/homepage" })
public class AdminHomePage extends HttpServlet {
	private static final long serialVersionUID = 1L;

	IAdminService adminService = new AdminServiceImpl();

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		List<Admin> adminList = adminService.getAll();
		request.setAttribute("adminlist", adminList);
		RequestDispatcher dispatcher = request.getRequestDispatcher("/view/admin/admin.jsp");
		dispatcher.forward(request, response);
	}

}
