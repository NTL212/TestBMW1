package vn.iotstar.Dao;

import java.util.List;

import vn.iotstar.Entity.Product;

public interface IProductDao {

	int countAll();

	List<Product> findAll(int page, int pagesize);

	List<Product> searchByName(String keyword);

	List<Product> findAll();

	Product get(int ProductId);

	void delete(int productid) throws Exception;

	void update(Product product);

	void insert(Product product);

	List<Product> getProductById(int id);

}
