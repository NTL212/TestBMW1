package vn.iotstar.Controller.admin;

import java.io.IOException;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Entity.Category;
import vn.iotstar.Entity.Product;
import vn.iotstar.Service.ICategoryService;
import vn.iotstar.Service.IProductService;
import vn.iotstar.Service.Impl.CategoryServiceImpl;
import vn.iotstar.Service.Impl.ProductServiceImpl;

/**
 * Servlet implementation class ProductEditController
 */
@WebServlet(urlPatterns = { "/admin/product/update" })
public class ProductEditController extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	IProductService productService = new ProductServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		ICategoryService cateService = new CategoryServiceImpl();
		List<Category> cateList = cateService.findAll();
		req.setAttribute("catelist", cateList);

		String id = req.getParameter("id");
		Product product = productService.get(Integer.parseInt(id));
		req.setAttribute("product", product);

		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/admin/editproduct.jsp");
		dispatcher.forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("utf-8");
		resp.setContentType("text/html;charset=UTF-8");
		Product product = new Product();
		Category cate = new Category();
		cate.setId(Integer.parseInt(req.getParameter("product-cate")));
		product.setId(Integer.parseInt(req.getParameter("product-sku")));
		product.setCategory_id(cate);
		product.setName(req.getParameter("product-name"));
		product.setPrice(req.getParameter("product-price"));
		product.setStatus(Integer.parseInt(req.getParameter("product-status")));
		product.setDescription(req.getParameter("product-desc"));
		product.setContent(req.getParameter("product-content"));
		product.setDiscount(Integer.parseInt(req.getParameter("product-discount")));
		product.setImage_link(req.getParameter("product-image"));
		product.setCreated(req.getParameter("product-day"));
		productService.update(product);

		resp.sendRedirect(req.getContextPath() + "/admin/product/list");

	}
}