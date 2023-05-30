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

/**
 * Servlet implementation class CategoryAddController
 */
@WebServlet(urlPatterns = { "/admin/category/add" })
public class CategoryAddController extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	ICategoryService cateService = new CategoryServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/admin/addcate.jsp");
		dispatcher.forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("utf-8");
		resp.setContentType("text/html;charset=UTF-8");
		String cate_name = req.getParameter("cate-name");
		String cate_parent_id = req.getParameter("parent-id");
		Category category = new Category();
		category.setName(cate_name);
		category.setParent_id(Integer.parseInt(cate_parent_id));
		cateService.insert(category);
		resp.sendRedirect(req.getContextPath() + "/admin/category/list");
	}

}
