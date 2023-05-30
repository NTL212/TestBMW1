package vn.iotstar.Controller.admin;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vn.iotstar.Entity.Category;
import vn.iotstar.Service.ICategoryService;
import vn.iotstar.Service.Impl.CategoryServiceImpl;

import java.util.List;

/**
 * Servlet implementation class CategoryListController
 */
@WebServlet(urlPatterns = { "/admin/category/list" })
public class CategoryListController extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	ICategoryService cateService = new CategoryServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		List<Category> cateList = cateService.findAll();
		req.setAttribute("catelist", cateList);
		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/admin/show-cate.jsp");
		dispatcher.forward(req, resp);
	}

}