package vn.iotstar.Controller.admin;

import java.io.IOException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Entity.Product;
import vn.iotstar.Service.IProductService;
import vn.iotstar.Service.Impl.ProductServiceImpl;

/**
 * Servlet implementation class ProductListController
 */
@WebServlet(urlPatterns = { "/admin/product/list" })
public class ProductListController extends HttpServlet {
	private static final long serialVersionUID = 1L;

	IProductService productService = new ProductServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		List<Product> productList = productService.findAll();
		req.setAttribute("productlist", productList);
		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/admin/show-product.jsp");
		dispatcher.forward(req, resp);
	}
}
