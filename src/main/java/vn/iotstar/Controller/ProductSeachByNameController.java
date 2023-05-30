package vn.iotstar.Controller;

import java.io.IOException;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
import java.net.URLEncoder;
import org.owasp.encoder.Encode;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.errors.IntrusionException;
import org.owasp.esapi.errors.ValidationException;

import vn.iotstar.Entity.Category;
import vn.iotstar.Entity.Product;
import vn.iotstar.Service.ICategoryService;
import vn.iotstar.Service.IProductService;
import vn.iotstar.Service.Impl.CategoryServiceImpl;
import vn.iotstar.Service.Impl.ProductServiceImpl;


@WebServlet(urlPatterns = { "/view/client/product/search" })
public class ProductSeachByNameController extends HttpServlet {
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    ICategoryService cateService = new CategoryServiceImpl();
    IProductService productService=new ProductServiceImpl();
    DecimalFormat df = new DecimalFormat("#.000");
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    	
        String name = StringEscapeUtils.escapeHtml4(req.getParameter("s")); // Mã hóa đầu vào để ngăn chặn XSS
        List<Category> cateList = cateService.findAll();
        req.setAttribute("catelist", cateList);
        
        List<Product> productSeachByName = productService.searchByName(name);
        req.setAttribute("productlist", productSeachByName);
    
        List<Product> productAllList = productService.findAll();
        req.setAttribute("product_all", productAllList);
        
        List<Product> productsList1 = new ArrayList<Product>();
        for (Product product : productSeachByName) {
            Product product1 = productService.get(product.getId());
            product1.setPrice(String.valueOf(df.format(Double.parseDouble(product.getPrice()) * (1 - (Double.parseDouble(Integer.toString(product.getDiscount())) / 100)))));
            productsList1.add(product1);
            
        }

        req.setAttribute("productlist1", productsList1);
        // Product bán chạy
        List<Product> product_banchay = productService.getProductById(6);
        req.setAttribute("product_banchay", product_banchay);    
        
        RequestDispatcher dispatcher = req.getRequestDispatcher("/view/client/product-search.jsp");
        try {
        	dispatcher.forward(req, resp);
        } catch (IllegalStateException e) {
            // Handle the bad request here, e.g., redirect to an error page
        	req.getRequestDispatcher("/view/client/index.jsp").forward(req, resp);
        }
        dispatcher.forward(req, resp);
        System.out.print(name);
    }
}
