package vn.iotstar.Controller.admin;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Entity.User;
import vn.iotstar.Service.IUserService;
import vn.iotstar.Service.Impl.UserServiceImpl;

import java.util.List;
@WebServlet(urlPatterns = { "/admin/user/list" })
public class UserListController extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	IUserService userService = new UserServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		List<User> users = userService.findAll();
		req.setAttribute("userList", users);
		RequestDispatcher dispatcherUser = req.getRequestDispatcher("/view/admin/user.jsp");
		dispatcherUser.forward(req, resp);
	}
}