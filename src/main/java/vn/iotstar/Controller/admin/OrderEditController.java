
package vn.iotstar.Controller.admin;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Entity.OrderItem;
import vn.iotstar.Service.IOrderItemService;
import vn.iotstar.Service.Impl.OrderItemServiceImpl;
@WebServlet(urlPatterns = { "/admin/order/update" })
public class OrderEditController extends HttpServlet {
	/**
	* 
	*/
	private static final long serialVersionUID = 1L;
	IOrderItemService orderItemService = new OrderItemServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		String id = req.getParameter("id");
		OrderItem transaction = orderItemService.get(Integer.parseInt(id));
		req.setAttribute("order", transaction);

		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/admin/editorder.jsp");
		dispatcher.forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("utf-8");
		resp.setContentType("text/html;charset=UTF-8");
		OrderItem orderItem = new OrderItem();
		orderItem.setId(Integer.parseInt(req.getParameter("order-id")));
		orderItem.setUser_name(req.getParameter("order-name"));
		orderItem.setUser_session(req.getParameter("user_session"));
		orderItem.setUser_mail(req.getParameter("order-mail"));
		orderItem.setUser_phone(req.getParameter("order-phone"));
		orderItem.setAddress(req.getParameter("order-address"));
		orderItem.setMessage(req.getParameter("order-mess"));
		orderItem.setAmount(req.getParameter("order-amount"));
		orderItem.setPayment(req.getParameter("order-payment"));
		orderItem.setStatus(req.getParameter("order-status"));
		orderItemService.edit(orderItem);
		resp.sendRedirect(req.getContextPath() + "/admin/order/list");

	}
}
