package vn.iotstar.Dao.Impl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

import vn.iotstar.Dao.IProductDao;
import vn.iotstar.Entity.Product;
import vn.iotstar.JPAConfig.JpaConfig;

public class ProductDaoImpl implements IProductDao {
	@Override
	public void insert(Product product) {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		enma.persist(product);
		trans.commit();
		} catch (Exception e) {
		e.printStackTrace();
		trans.rollback();
		throw e;
		}finally {
		enma.close();
		}
	}
	@Override
	public void update(Product product) {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		enma.merge(product);
		trans.commit();
		} catch (Exception e) {
		e.printStackTrace();
		trans.rollback();
		throw e;
		}finally {
		enma.close();
		}
	}
	@Override
	public void delete(int productid) throws Exception {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		Product product = enma.find(Product.class,productid);
		if(product != null) {
		enma.remove(product);
		}else {
		throw new Exception("Không tìm thấy");
		}
		trans.commit();
		} catch (Exception e) {
		e.printStackTrace();
		trans.rollback();
		throw e;
		}finally {
		enma.close();
		}
	}
	@Override
	public Product get(int ProductId){
		EntityManager enma = JpaConfig.getEntityManager();
		Product product = enma.find(Product.class,ProductId);
		return product;
	}
	@Override
	public List<Product> getProductById(int id) {
		EntityManager enma = JpaConfig.getEntityManager();
		String jpql = "SELECT p FROM Product p WHERE p.category_id.id LIKE ?1";
		TypedQuery<Product> query= enma.createQuery(jpql, Product.class);
		query.setParameter(1,id);
		return query.getResultList();
	}
	
	
	@Override
	public List<Product> findAll(){
		EntityManager enma = JpaConfig.getEntityManager();
		TypedQuery<Product> query= enma.createNamedQuery("Product.findAll", Product.class);
		return query.getResultList();
	}
	@Override
	public List<Product> searchByName(String keyword){
		EntityManager enma = JpaConfig.getEntityManager();
		String jpql = "SELECT p FROM Product p WHERE name like :keyword";
		TypedQuery<Product> query= enma.createQuery(jpql, Product.class);
		query.setParameter("keyword", "%" + keyword + "%");
		return query.getResultList();
	}
	@Override
	public List<Product> findAll(int page,int pagesize){
		EntityManager enma = JpaConfig.getEntityManager();
		TypedQuery<Product> query= enma.createNamedQuery("Product.findAll", Product.class);
		query.setFirstResult(page*pagesize);
		query.setMaxResults(pagesize);
		return query.getResultList();
	}
	@Override
	public int countAll(){
		EntityManager enma = JpaConfig.getEntityManager();
		String jpql = "SELECT count(p) FROM Product p";
		Query query = enma.createQuery(jpql);
		return ((Long)query.getSingleResult()).intValue();
		}
	
}
