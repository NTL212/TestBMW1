package vn.iotstar.Dao;

import java.util.List;

import vn.iotstar.Entity.Category;

public interface ICategoryDao {

	Category get(int categoryId);

	void delete(int cateid) throws Exception;

	void update(Category category);

	void insert(Category category);

	List<Category> findAll();

	List<Category> getCateByProduct(int id);

}
