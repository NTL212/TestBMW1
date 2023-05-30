package vn.iotstar.Controller.admin;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Service.IUserService;
import vn.iotstar.Service.Impl.UserServiceImpl;
@WebServlet(urlPatterns = { "/admin/user/delete" })
public class UserDeleteController extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	IUserService userService = new UserServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		int user_id = Integer.parseInt(req.getParameter("user-id"));
		try {
			userService.delete(user_id);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		req.setAttribute("userList", userService.findAll());
		RequestDispatcher dispatcherUser = req.getRequestDispatcher("/view/admin/user.jsp");
		dispatcherUser.forward(req, resp);
	}
}