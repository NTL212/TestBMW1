package vn.iotstar.Controller;

import java.io.IOException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;

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
 * Servlet implementation class CategoryListController
 */
@WebServlet(urlPatterns = { "/view/client/product", "/view/client/product-id" })
public class ProductListClientController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	ICategoryService cateService = new CategoryServiceImpl();
	IProductService productService = new ProductServiceImpl();
	DecimalFormat df = new DecimalFormat("#.000");

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();
		if (url.contains("product-id")) {
			productlistbycate(req, resp);
		} else {
			productlist(req, resp);

		}
	}

	protected void productlist(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		List<Category> cateList = cateService.findAll();
		req.setAttribute("catelist", cateList);
		String indexpage = req.getParameter("index");
		if (indexpage == null) {
			indexpage = "1";
		}
		int index = Integer.parseInt(indexpage);
		int countP = productService.countAll();
		int endpage = countP / 6;
		if (countP % 6 != 0) {
			endpage++;
		}
		List<Product> productList = productService.findAll(index - 1, 6);
		req.setAttribute("endP", endpage);
		req.setAttribute("tag", index);
		req.setAttribute("productlist", productList);

		List<Product> productsList1 = new ArrayList<Product>();
		for (Product product : productList) {
			Product product1 = productService.get(product.getId());
			product1.setPrice(String
					.valueOf(df.format(Double.parseDouble(product.getPrice()) * (1 - (product.getDiscount() / 100)))));
			productsList1.add(product1);

		}
		req.getRequestDispatcher("/view/client/product.jsp").forward(req, resp);
	}

	protected void productlistbycate(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		List<Category> cateList = cateService.findAll();
		req.setAttribute("catelist", cateList);
		String id = req.getParameter("id");
		if (id == null) {
			req.getRequestDispatcher("/view/client/product.jsp").forward(req, resp);
		}
		List<Product> productList = productService.getProductById(Integer.parseInt(id));

		req.setAttribute("productlist", productList);

		List<Product> productsList1 = new ArrayList<Product>();
		for (Product product : productList) {
			Product product1 = productService.get(product.getId());
			product1.setPrice(String
					.valueOf(df.format(Double.parseDouble(product.getPrice()) * (1 - (product.getDiscount() / 100)))));
			productsList1.add(product1);

		}

		req.setAttribute("productlist1", productsList1);

		List<Product> product_banchay = productService.getProductById(6);
		req.setAttribute("product_banchay", product_banchay);
		req.getRequestDispatcher("/view/client/product.jsp").forward(req, resp);
	}

}
