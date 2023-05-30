package vn.iotstar.Service;

import java.util.List;

import vn.iotstar.Entity.Admin;

public interface IAdminService {
	void insert(Admin admin); 
	 
	void update(Admin admin); 
	
	void delete(int id)  throws Exception ; 
 
	Admin get(int id); 
	 
	Admin get(String name); 
 
	List<Admin> getAll(); 
	Admin checkAdminLogin(String username,String password);
}
