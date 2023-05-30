package vn.iotstar.Service;

import java.util.List;

import vn.iotstar.Entity.Ordered;

public interface IOrderedService {
	void insert(Ordered ordered); 
	 
	void edit(Ordered ordered); 

	void delete(String id) throws Exception; 
 
	Ordered get(int id); 
	 
	Ordered get(String name); 
 
	List<Ordered> getAll(); 
}
