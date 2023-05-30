package vn.iotstar.Service;

import java.util.List;

import vn.iotstar.Entity.Category;

public interface ICategoryService {
	Category get(int categoryId);

	void delete(int cateid) throws Exception;

	void update(Category category);

	void insert(Category category);

	List<Category> findAll();

	List<Category> getCateByProduct(int id);
}
