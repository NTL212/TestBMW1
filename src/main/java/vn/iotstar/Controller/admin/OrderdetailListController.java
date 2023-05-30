
package vn.iotstar.Controller.admin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Entity.Ordered;
import vn.iotstar.Entity.Product;
import vn.iotstar.Service.IOrderedService;
import vn.iotstar.Service.IProductService;
import vn.iotstar.Service.Impl.OrderedServiceImpl;
import vn.iotstar.Service.Impl.ProductServiceImpl;

@WebServlet(urlPatterns = { "/admin/order/list-detail" })
public class OrderdetailListController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IOrderedService orderedServcie = new OrderedServiceImpl();
	IProductService productService = new ProductServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		List<Ordered> orderedList = orderedServcie.getAll();
		req.setAttribute("orderedlist", orderedList);
		List<Product> products = new ArrayList<Product>();
		for (Ordered ordered : orderedList) {
			Product product = new Product();
			product = productService.get(ordered.getProduct_id().getId());
			products.add(product);
		}
		req.setAttribute("products", products);
		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/admin/show-orderdetail.jsp");
		dispatcher.forward(req, resp);
	}
}
