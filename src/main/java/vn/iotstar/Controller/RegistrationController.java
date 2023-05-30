package vn.iotstar.Controller;

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

/**
 * Servlet implementation class RegistrationController
 */
@WebServlet(urlPatterns = { "/view/client/register" })
public class RegistrationController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IUserService userservice = new UserServiceImpl();

	public RegistrationController() {
		super();
	}

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		RequestDispatcher dispatcher = this.getServletContext().getRequestDispatcher("/view/client/register.jsp");
		dispatcher.forward(request, response);
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		response.setContentType("text/html");
		request.setCharacterEncoding("utf-8");
		response.setContentType("text/html;charset=UTF-8");
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		String email = request.getParameter("email");
		String phone = request.getParameter("phone");
		String name = request.getParameter("name");
		String created = request.getParameter("created");

		User user = new User(name, email, phone, username, password, created);
		int register = userservice.RegisterUser(user);
		System.out.println(register);
		if (register == 0) // On success, you can display a message to user on Home page
		{
			request.setAttribute("Message",
					"Tạo tài khoản thành công.Đăng nhập <a href='/DoAnLTWeb/view/client/login'>tại đây!</a>");
			RequestDispatcher rd = request.getRequestDispatcher("/view/client/register.jsp");
			rd.forward(request, response);
		} else if(register == 1){
			request.setAttribute("errMessage", "Đã tồn tại email!!!");
			RequestDispatcher rd = request.getRequestDispatcher("/view/client/register.jsp");
			rd.forward(request, response);
		}else if(register == 2){
			request.setAttribute("errMessage", "Đã tồn tại username!!!");
			RequestDispatcher rd = request.getRequestDispatcher("/view/client/register.jsp");
			rd.forward(request, response);
		}
	}
}
