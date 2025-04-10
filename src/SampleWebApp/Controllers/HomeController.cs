using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace SampleWebApp.Controllers
{
	public class HomeController : Controller
	{
		public ActionResult Index()
		{
            bool isAuthenticated = HttpContext.GetOwinContext().Authentication.User != null ? HttpContext.GetOwinContext().Authentication.User.Identity.IsAuthenticated : false;
            ViewBag.IsAuthenticated = isAuthenticated;
            return View();
		}

		[Authorize]
		public ActionResult About()
		{
            ViewBag.Message = "Your application description page.";

			return View();
		}

		public ActionResult Contact()
		{
            ViewBag.Message = "Your contact page.";

			return View();
		}

		public ActionResult Callback() {

            //do whatever your app requires or delete this method
            return RedirectToAction("Index");
        }

        public ActionResult Error(string error)
        {
            ViewBag.Error = error;
            return View();
        }

        [Authorize]
        public ActionResult Logout()
        {

            bool isAuthenticated = HttpContext.GetOwinContext().Authentication.User.Identity.IsAuthenticated;
            HttpContext.GetOwinContext().Authentication.SignOut();
            return RedirectToAction("Index");
        }

        public void LoggedOut()
        {
            bool isAuthenticated = HttpContext.GetOwinContext().Authentication.User.Identity.IsAuthenticated;
        }
    }
}