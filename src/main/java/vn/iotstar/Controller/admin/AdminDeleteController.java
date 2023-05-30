package vn.iotstar.Controller.admin;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Service.IAdminService;
import vn.iotstar.Service.Impl.AdminServiceImpl;
@WebServlet(urlPatterns = { "/admin/admin/delete" })
public class AdminDeleteController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IAdminService adminService = new AdminServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String admin_id = req.getParameter("admin-id");
		try {
			adminService.delete(Integer.parseInt(admin_id));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		req.setAttribute("adminlist", adminService.getAll());
		RequestDispatcher dispatcherUser = req.getRequestDispatcher("/view/admin/admin.jsp");
		dispatcherUser.forward(req, resp);
	}
}
