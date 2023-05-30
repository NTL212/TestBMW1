package vn.iotstar.Service.Impl;

import java.util.List;

import vn.iotstar.Dao.IProductDao;
import vn.iotstar.Dao.Impl.ProductDaoImpl;
import vn.iotstar.Entity.Product;
import vn.iotstar.Service.IProductService;

public class ProductServiceImpl implements IProductService {
	IProductDao productDao = new ProductDaoImpl();
	@Override
	public int countAll() {
		return productDao.countAll();
	}

	@Override
	public List<Product> findAll(int page, int pagesize) {
		return productDao.findAll(page,pagesize);
	}

	@Override
	public List<Product> searchByName(String keyword) {
		return productDao.searchByName(keyword);
	}

	@Override
	public List<Product> findAll() {
		return productDao.findAll();
	}

	@Override
	public Product get(int ProductId) {
		return productDao.get(ProductId);
	}

	@Override
	public void delete(int productid) throws Exception {
		productDao.delete(productid);
		
	}

	@Override
	public void update(Product product) {
		productDao.update(product);
		
	}

	@Override
	public void insert(Product product) {
		productDao.insert(product);
	}

	@Override
	public List<Product> getProductById(int id) {
		return productDao.getProductById(id);
	}

}
