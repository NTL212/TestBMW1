package vn.iotstar.Dao.Impl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.TypedQuery;

import vn.iotstar.Dao.IOrderedDao;
import vn.iotstar.Entity.Ordered;
import vn.iotstar.JPAConfig.JpaConfig;

public class OrderedDaoImpl implements IOrderedDao {

	@Override
	public void insert(Ordered ordered) {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		enma.persist(ordered);
		trans.commit();
		} catch (Exception e) {
		e.printStackTrace();
		trans.rollback();
		}
	}

	@Override
	public void edit(Ordered ordered) {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		enma.merge(ordered);
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
	public void delete(String id) throws Exception {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
		trans.begin();
		Ordered ordered = enma.find(Ordered.class,id);
		if(ordered != null) {
		enma.remove(ordered);
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
	public Ordered get(int id) {
		EntityManager enma = JpaConfig.getEntityManager();
		Ordered ordered = enma.find(Ordered.class,id);
		return ordered;
	}

	@Override
	public Ordered get(String name) {
		return null;
	}

	@Override
	public List<Ordered> getAll() {
		EntityManager enma = JpaConfig.getEntityManager();
		TypedQuery<Ordered> query= enma.createNamedQuery("Ordered.findAll", Ordered.class);
		return query.getResultList();
	}

}
