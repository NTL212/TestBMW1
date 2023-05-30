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
 * Servlet implementation class CatagoryEditController
 */
@WebServlet(urlPatterns = { "/admin/category/update" })
public class CategoryEditController extends HttpServlet {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	ICategoryService cateService = new CategoryServiceImpl();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String id = req.getParameter("id");
		Category catelist = cateService.get(Integer.parseInt(id));
		req.setAttribute("catelist", catelist);

		RequestDispatcher dispatcher = req.getRequestDispatcher("/view/admin/editcate.jsp");
		dispatcher.forward(req, resp);
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("utf-8");
		resp.setContentType("text/html;charset=UTF-8");
		Category category = new Category();
		category.setName(req.getParameter("name"));
		category.setParent_id(Integer.parseInt(req.getParameter("parent-id")));
		category.setId(Integer.parseInt(req.getParameter("id")));
		cateService.update(category);

		resp.sendRedirect(req.getContextPath() + "/admin/category/list");

	}
}