package vn.iotstar.Dao;

import java.util.List;

import vn.iotstar.Entity.OrderItem;

public interface IOrderItemDao {
	void insert(OrderItem orderitem); 
	 
	void edit(OrderItem admin); 
	
	void delete(int id) throws Exception; 
 
	OrderItem get(int id); 
	 
	OrderItem get(String name); 
 
	List<OrderItem> getAll(); 
}
