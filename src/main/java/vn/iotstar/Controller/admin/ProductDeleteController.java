package vn.iotstar.Controller.admin;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Service.IProductService;
import vn.iotstar.Service.Impl.ProductServiceImpl;

/**
 * Servlet implementation class CatagoryDeleteController
 */
@WebServlet(urlPatterns = { "/admin/product/delete" })
public class ProductDeleteController extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	IProductService productService = new ProductServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String id = req.getParameter("id");
		try {
			productService.delete(Integer.parseInt(id));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		resp.sendRedirect(req.getContextPath() + "/admin/product/list");
	}

}
