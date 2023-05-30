package vn.iotstar.Controller;

import java.io.IOException;
import java.text.DecimalFormat;
import java.util.ArrayList;
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
import vn.iotstar.Entity.Product;
import vn.iotstar.Service.IProductService;
import vn.iotstar.Service.Impl.ProductServiceImpl;

/**
 * Servlet implementation class AddToCartController
 */
@WebServlet(urlPatterns = {"/view/client/add-cart" })
public class AddToCartController extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
	IProductService productService = new ProductServiceImpl();
	DecimalFormat df = new DecimalFormat("#.000");
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		int n= 0;
		int qty = 1;
		String id;
		
		if(request.getParameter("product-id")!=null) {
			id = request.getParameter("product-id");
			Product product = productService.get(Integer.parseInt(id));;
			if(product != null) {
				if(request.getParameter("qty")!=null) {
					qty = Integer.parseInt(request.getParameter("qty"));
				}
				
				HttpSession session = request.getSession();
				if(session.getAttribute("order") == null) {
					Order order = new Order();
					List<Item> listItems = new ArrayList<Item>();
					
					Item item = new Item();
					item.setQty(qty);
					item.setProduct(product);
					item.setPrice(Double.parseDouble(product.getPrice()) - Double.parseDouble(product.getPrice())*((double)product.getDiscount())/100);//getDiscount là số
					order.setSumPrice(0);
					order.setSumPrice(order.getSumPrice() + item.getPrice());
					listItems.add(item);
					order.setItems(listItems);
					n = listItems.size();
					session.setAttribute("length_order",n);
					session.setAttribute("order", order);
					session.setAttribute("sumprice", df.format(order.getSumPrice()));
				} else {
					Order order = (Order) session.getAttribute("order");
					List<Item> listItems = order.getItems();
					boolean check = false;
					for(Item item : listItems) {
						if(item.getProduct().getId() == product.getId()) 
						{
							item.setQty(item.getQty() + qty);
							order.setSumPrice(order.getSumPrice() + Double.parseDouble(item.getProduct().getPrice()) - Double.parseDouble(item.getProduct().getPrice())*((double)item.getProduct().getDiscount())/100);
							item.setPrice(item.getPrice() + (Double.parseDouble(item.getProduct().getPrice()) - Double.parseDouble(item.getProduct().getPrice())*((double)item.getProduct().getDiscount())/100));
							check = true;
						}
					}
					if(check == false) {
						Item item = new Item();
						item.setQty(qty);
						item.setProduct(product);
						item.setPrice(Double.parseDouble(product.getPrice()) - Double.parseDouble(item.getProduct().getPrice())*((double)item.getProduct().getDiscount())/100);
						order.setSumPrice(order.getSumPrice() + Double.parseDouble(item.getProduct().getPrice()) - Double.parseDouble(item.getProduct().getPrice())*((double)item.getProduct().getDiscount())/100);
						listItems.add(item);
					}
					n = listItems.size();
					session.setAttribute("length_order",n);
					session.setAttribute("order", order);
					session.setAttribute("sumprice", df.format(order.getSumPrice()));
				}
			}
			RequestDispatcher dispatcher = request.getRequestDispatcher("/view/client/cart.jsp");
			dispatcher.forward(request, response);
		} else {
			response.sendRedirect(request.getContextPath() + "/");
		}
		
	}

}
