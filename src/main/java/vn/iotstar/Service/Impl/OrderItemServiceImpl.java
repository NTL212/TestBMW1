package vn.iotstar.Service.Impl;

import java.util.List;

import vn.iotstar.Dao.IOrderItemDao;
import vn.iotstar.Dao.Impl.OrderItemDaoImpl;
import vn.iotstar.Entity.OrderItem;
import vn.iotstar.Service.IOrderItemService;

public class OrderItemServiceImpl implements IOrderItemService{
	IOrderItemDao orderItemDao = new OrderItemDaoImpl();
	
	@Override
	public void insert(OrderItem OrderItem) {
		orderItemDao.insert(OrderItem);
		
	}

	@Override
	public void edit(OrderItem OrderItem) {
		orderItemDao.edit(OrderItem);
		
	}

	@Override
	public void delete(int id) throws Exception {
		orderItemDao.delete(id);
		
	}
	@Override
	public OrderItem get(int id) {
		return orderItemDao.get(id);
	}

	@Override
	public OrderItem get(String name) {
		return orderItemDao.get(name);
	}

	@Override
	public List<OrderItem> getAll() {
		return orderItemDao.getAll();
	}

}
