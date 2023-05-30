
package vn.iotstar.Controller.admin;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Service.IOrderItemService;
import vn.iotstar.Service.Impl.OrderItemServiceImpl;

@WebServlet(urlPatterns = { "/admin/order/delete" })
public class OrderDeleteController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IOrderItemService orderItemService = new OrderItemServiceImpl();

	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String id = req.getParameter("id");
		try {
			orderItemService.delete(Integer.parseInt(id));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		resp.sendRedirect(req.getContextPath() + "/admin/order/list");
	}
}
