package vn.iotstar.Service.Impl;

import java.util.List;

import vn.iotstar.Dao.IAdminDao;
import vn.iotstar.Dao.Impl.AdminDaoImpl;
import vn.iotstar.Entity.Admin;
import vn.iotstar.Service.IAdminService;

public class AdminServiceImpl implements IAdminService {
	IAdminDao admindao = new AdminDaoImpl();

	@Override
	public void insert(Admin admin) {
		admindao.insert(admin);

	}

	@Override
	public void update(Admin admin) {
		admindao.update(admin);

	}

	@Override
	public void delete(int id) throws Exception {
		admindao.delete(id);

	}

	@Override
	public Admin get(int id) {
		return admindao.get(id);
	}

	@Override
	public Admin get(String name) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<Admin> getAll() {
		return admindao.getAll();
	}

	@Override
	public Admin checkAdminLogin(String username, String password) {
		return admindao.checkAdminLogin(username, password);
	}

}
