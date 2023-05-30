package vn.iotstar.Service.Impl;

import java.util.List;

import vn.iotstar.Dao.Impl.CategoryDaoImpl;
import vn.iotstar.Dao.ICategoryDao;
import vn.iotstar.Entity.Category;
import vn.iotstar.Service.ICategoryService;

public class CategoryServiceImpl implements ICategoryService {
	
	ICategoryDao categoryDao =new CategoryDaoImpl();
	@Override
	public Category get(int categoryId) {
		return categoryDao.get(categoryId);
	}

	@Override
	public void delete(int cateid) throws Exception {
		categoryDao.delete(cateid);
		
	}

	@Override
	public void update(Category category) {
		categoryDao.update(category);
	}

	@Override
	public void insert(Category category) {
		categoryDao.insert(category);
		
	}

	@Override
	public List<Category> findAll() {
		return categoryDao.findAll();
	}

	@Override
	public List<Category> getCateByProduct(int id) {
		return categoryDao.getCateByProduct(id);
	}

}
