package vn.iotstar.Dao.Impl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.TypedQuery;

import vn.iotstar.Dao.IAdminDao;
import vn.iotstar.Entity.Admin;
import vn.iotstar.JPAConfig.JpaConfig;

public class AdminDaoImpl implements IAdminDao {
	@Override
	public void insert(Admin admin) {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		enma.persist(admin);
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
	public void update(Admin admin) {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		enma.merge(admin);
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
	public void delete(int id) throws Exception {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		Admin admin = enma.find(Admin.class,id);
		if(admin != null) {
		enma.remove(admin);
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
	public Admin get(int id) {
		EntityManager enma = JpaConfig.getEntityManager();
		Admin admin = enma.find(Admin.class,id);
		return admin;
	}

	@Override
	public Admin get(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<Admin> getAll() {
		EntityManager enma = JpaConfig.getEntityManager();
		TypedQuery<Admin> query= enma.createNamedQuery("Admin.findAll", Admin.class);
		return query.getResultList();
	}

	@Override
	public Admin checkAdminLogin(String username, String password) {
		EntityManager enma = JpaConfig.getEntityManager();
		String jpql = "SELECT a FROM Admin a WHERE a.username like :username and a.password like :password";
		TypedQuery<Admin> query= enma.createQuery(jpql, Admin.class);
		query.setParameter("username",username);
		query.setParameter("password",password);
		try {
		return query.getSingleResult();
		}
		catch(Exception e) {
			return null;
		}
	}
}
