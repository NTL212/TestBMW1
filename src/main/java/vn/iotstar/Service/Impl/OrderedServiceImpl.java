package vn.iotstar.Service.Impl;

import java.util.List;

import vn.iotstar.Dao.IOrderedDao;
import vn.iotstar.Dao.Impl.OrderedDaoImpl;
import vn.iotstar.Entity.Ordered;
import vn.iotstar.Service.IOrderedService;

public class OrderedServiceImpl implements IOrderedService {
	IOrderedDao orderedDao = new OrderedDaoImpl();

	@Override
	public void insert(Ordered ordered) {
		orderedDao.insert(ordered);
	}

	@Override
	public void edit(Ordered ordered) {
		orderedDao.edit(ordered);

	}

	@Override
	public void delete(String id) throws Exception {
		orderedDao.delete(id);

	}

	@Override
	public Ordered get(int id) {
		return orderedDao.get(id);
	}

	@Override
	public Ordered get(String name) {
		return orderedDao.get(name);
	}

	@Override
	public List<Ordered> getAll() {
		return orderedDao.getAll();
	}

}
