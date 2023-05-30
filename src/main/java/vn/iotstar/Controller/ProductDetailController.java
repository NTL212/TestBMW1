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

import vn.iotstar.Entity.Category;
import vn.iotstar.Entity.Product;
import vn.iotstar.Service.ICategoryService;
import vn.iotstar.Service.IProductService;
import vn.iotstar.Service.Impl.CategoryServiceImpl;
import vn.iotstar.Service.Impl.ProductServiceImpl;

@WebServlet(urlPatterns = { "/view/client/product-detail" })
public class ProductDetailController extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	ICategoryService cateService = new CategoryServiceImpl();
	IProductService productService = new ProductServiceImpl();
	DecimalFormat df = new DecimalFormat("#.000");

	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String id = req.getParameter("id");
		Product detail_product = productService.get(Integer.parseInt(id));
		req.setAttribute("detail_product", detail_product);

		List<Category> name_cate_of_product = cateService.getCateByProduct(Integer.parseInt(id));
		req.setAttribute("name_cate_of_product", name_cate_of_product);

		Category idCate = detail_product.getCategory_id();

		List<Product> productListCate = productService.getProductById(idCate.getId());

		req.setAttribute("productById", productListCate);

		List<Product> productList = productService.findAll();
		req.setAttribute("productlist", productList);

		List<Product> productsList1 = new ArrayList<Product>();
		for (Product product : productList) {
			Product product1 = productService.get(product.getId());
			product1.setPrice(String
					.valueOf(df.format(Double.parseDouble(product.getPrice()) * (1 - (product.getDiscount() / 100)))));
			productsList1.add(product1);
		}

		req.setAttribute("productlist1", productsList1);

		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/client/product-detail.jsp");
		dispatcher.forward(req, resp);
	}

}
