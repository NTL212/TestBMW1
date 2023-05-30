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

import vn.iotstar.Service.IProductService;
import vn.iotstar.Entity.Product;
import vn.iotstar.Service.Impl.ProductServiceImpl;

@WebServlet(urlPatterns = { "" })
public class HomeController extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	IProductService productService = new ProductServiceImpl();
	DecimalFormat df = new DecimalFormat("#.000");

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		List<Product> product_raucu = productService.getProductById(1);
		req.setAttribute("product_raucu", product_raucu);

		List<Product> product_hat = productService.getProductById(2);
		req.setAttribute("product_hat", product_hat);

		List<Product> product_traicay = productService.getProductById(3);
		req.setAttribute("product_traicay", product_traicay);

		List<Product> productList = productService.findAll();
		req.setAttribute("productlist", productList);

		List<Product> productsList = new ArrayList<Product>();
		for (Product product : productList) {
			Product p = productService.get(product.getId());
			p.setPrice(String
					.valueOf(df.format(Double.parseDouble(product.getPrice()) * (1 - (product.getDiscount() / 100)))));
			productsList.add(p);
		}
		req.setAttribute("productlist1", productsList);

		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/client/index.jsp");
		dispatcher.forward(req, resp);
	}
}
