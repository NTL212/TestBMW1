package vn.iotstar.Controller;

import java.io.IOException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import vn.iotstar.Entity.Item;
import vn.iotstar.Entity.Order;
import vn.iotstar.Entity.OrderItem;
import vn.iotstar.Entity.Ordered;
import vn.iotstar.Service.IOrderItemService;
import vn.iotstar.Service.IOrderedService;
import vn.iotstar.Service.Impl.OrderItemServiceImpl;
import vn.iotstar.Service.Impl.OrderedServiceImpl;


/**
 * Servlet implementation class TransactionController
 */
@WebServlet("/view/client/checkout")
public class OrderItemController extends HttpServlet {
	private static final long serialVersionUID = 1L;

	IOrderItemService orderItemService = new OrderItemServiceImpl();
	IOrderedService orderedService = new OrderedServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/client/checkout.jsp");
		dispatcher.forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("utf-8");
		resp.setContentType("text/html;charset=UTF-8");
		String tr_usersession = req.getParameter("orderitem_usersession");
		String tr_username = req.getParameter("orderitem_name");
		String tr_usermail = req.getParameter("orderitem_email");
		String tr_userphone = req.getParameter("orderitem_phone");
		String tr_useraddress = req.getParameter("orderitem_address");
		String tr_usermess = req.getParameter("orderitem_mess");
		String tr_amount = req.getParameter("orderitem_amount");
		String tr_payment = req.getParameter("orderitem_payment");
		String tr_created = req.getParameter("orderitem_created");

		OrderItem orderitem = new OrderItem();
		orderitem.setUser_session(tr_usersession);
		orderitem.setUser_name(tr_username);
		orderitem.setUser_mail(tr_usermail);
		orderitem.setUser_phone(tr_userphone);
		orderitem.setAddress(tr_useraddress);
		orderitem.setMessage(tr_usermess);
		orderitem.setAmount(tr_amount);
		orderitem.setPayment(tr_payment);
		orderitem.setCreated(tr_created);
	
		orderItemService.insert(orderitem);

		int maxid =0;
		List<OrderItem> orderItem = orderItemService.getAll();
		if(orderItem.size() == 0)
		{
			maxid = 0;
		}
		else {
			for(OrderItem orderitems: orderItem)
			{
				if(orderitems.getId()>=maxid)
					maxid = orderitems.getId();
			}
		}
		HttpSession session = req.getSession(true);
		Order order = (Order) session.getAttribute("order");
		List<Item> listItems = order.getItems();
		for(Item item: listItems)
		{
			Ordered ordered = new Ordered();
			OrderItem or = new OrderItem();
			or.setId(maxid);
			ordered.setProduct_id(item.getProduct());
			ordered.setQty(item.getQty());
			ordered.setOrderitem_id(or);
			orderedService.insert(ordered);
		}
		 if (session != null) {
			 session.removeAttribute("order"); //remove session
			 session.removeAttribute("sumprice"); //remove session
			 session.removeAttribute("length_order"); //remove session
		 }
    resp.sendRedirect(req.getContextPath() + "/view/client/checkout");
		
	}


}
