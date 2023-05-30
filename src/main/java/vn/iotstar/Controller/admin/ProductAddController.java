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
@WebServlet(urlPatterns = { "/admin/product/add" })
public class ProductAddController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IProductService productService = new ProductServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		ICategoryService cateService = new CategoryServiceImpl();
		List<Category> cateList = cateService.findAll();
		req.setAttribute("catelist", cateList);
		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/admin/addproduct.jsp");
		dispatcher.forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("utf-8");
		resp.setContentType("text/html;charset=UTF-8");
		String product_cate = req.getParameter("product-cate");
		String product_name = req.getParameter("product-name");
		String product_price = req.getParameter("product-price");
		String product_status = req.getParameter("product-status");
		String product_desc = req.getParameter("product-desc");
		String product_content = req.getParameter("product-content");
		String product_discount = req.getParameter("product-discount");
		String product_image = req.getParameter("product-image");
		String product_day = req.getParameter("product-day");
		Category cate = new Category();
		cate.setId(Integer.parseInt(product_cate));
		Product product = new Product();
		product.setCategory_id(cate);
		product.setName(product_name);
		product.setPrice(product_price);
		product.setStatus(Integer.parseInt(product_status));
		product.setDescription(product_desc);
		product.setContent(product_content);
		product.setDiscount(Integer.parseInt(product_discount));
		product.setImage_link(product_image);
		product.setCreated(product_day);
		productService.insert(product);
		resp.sendRedirect(req.getContextPath() + "/admin/product/list");

	}
}
