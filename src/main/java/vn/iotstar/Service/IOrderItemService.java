package vn.iotstar.Service;

import java.util.List;

import vn.iotstar.Entity.OrderItem;

public interface IOrderItemService {
	void insert(OrderItem OrderItem);
	 
	void edit(OrderItem OrderItem); 

	void delete(int id) throws Exception; 
 
	OrderItem get(int id); 
	 
	OrderItem get(String name); 
 
	List<OrderItem> getAll(); 
}
