package vn.iotstar.Dao.Impl;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.TypedQuery;

import vn.iotstar.Dao.ICategoryDao;
import vn.iotstar.Entity.Category;
import vn.iotstar.JPAConfig.JpaConfig;

public class CategoryDaoImpl implements ICategoryDao{
	@Override
	public void insert(Category category) {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		enma.persist(category);
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
	public void update(Category category) {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		enma.merge(category);
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
	public void delete(int cateid) throws Exception {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		Category category = enma.find(Category.class,cateid);
		if(category != null) {
		enma.remove(category);
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
	public Category get(int categoryId){
		EntityManager enma = JpaConfig.getEntityManager();
		Category category = enma.find(Category.class,categoryId);
		return category;
	}
	@Override
	public List<Category> findAll(){
		EntityManager enma = JpaConfig.getEntityManager();
		TypedQuery<Category> query= enma.createNamedQuery("Category.findAll", Category.class);
		return query.getResultList();
	}
	@Override
	public List<Category> getCateByProduct(int id) {
		List<Category> products_cate = new ArrayList<Category>();
		EntityManager enma = JpaConfig.getEntityManager();
		String jpql = "SELECT c.name FROM Category c,Product p WHERE c.id = p.category_id and p.id LIKE :cateid";
		TypedQuery<String> query= enma.createQuery(jpql, String.class);
		query.setParameter("cateid",id);
		String name = query.getSingleResult();
		Category catagory_product = new Category();
		catagory_product.setName(name);
		products_cate.add(catagory_product);
		return products_cate;
	}
}
