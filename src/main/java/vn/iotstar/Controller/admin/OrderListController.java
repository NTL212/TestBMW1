
package vn.iotstar.Controller.admin;

import java.io.IOException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Entity.OrderItem;
import vn.iotstar.Service.IOrderItemService;
import vn.iotstar.Service.Impl.OrderItemServiceImpl;

/**
 * Servlet implementation class OrderListController
 */
@WebServlet(urlPatterns = { "/admin/order/list" })
public class OrderListController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IOrderItemService orderItemService = new OrderItemServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		List<OrderItem> transactionList = orderItemService.getAll();
		req.setAttribute("order", transactionList);
		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/admin/show-order.jsp");
		dispatcher.forward(req, resp);
	}

}
