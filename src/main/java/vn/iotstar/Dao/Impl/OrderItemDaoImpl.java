package vn.iotstar.Dao.Impl;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.TypedQuery;

import vn.iotstar.Dao.IOrderItemDao;
import vn.iotstar.Entity.OrderItem;
import vn.iotstar.JPAConfig.JpaConfig;

public class OrderItemDaoImpl implements IOrderItemDao {

	@Override
	public void insert(OrderItem OrderItem) {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
			trans.begin();
			enma.persist(OrderItem);
			trans.commit();
		} catch (Exception e) {
			e.printStackTrace();
			trans.rollback();
			throw e;
		} finally {
			enma.close();
		}
	}

	// ****
	@Override
	public void edit(OrderItem admin) {
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
		} finally {
			enma.close();
		}
	}

	@Override
	public void delete(int id) throws Exception {
		EntityManager enma = JpaConfig.getEntityManager();
		EntityTransaction trans = enma.getTransaction();
		try {
			trans.begin();
			OrderItem or = enma.find(OrderItem.class, id);
			if (or != null) {
				enma.remove(or);
			} else {
				throw new Exception("Không tìm thấy");
			}
			trans.commit();
		} catch (Exception e) {
			e.printStackTrace();
			trans.rollback();
			throw e;
		} finally {
			enma.close();
		}
	}

	@Override
	public OrderItem get(int id) {
		EntityManager enma = JpaConfig.getEntityManager();
		OrderItem orderItem = enma.find(OrderItem.class, id);
		return orderItem;
	}

	@Override
	public OrderItem get(String name) {
		EntityManager enma = JpaConfig.getEntityManager();
		OrderItem orderItem = enma.find(OrderItem.class, name);
		return orderItem;
	}

	@Override
	public List<OrderItem> getAll() {
		EntityManager enma = JpaConfig.getEntityManager();
		TypedQuery<OrderItem> query = enma.createNamedQuery("OrderItem.findAll", OrderItem.class);
		return query.getResultList();
	}

}
