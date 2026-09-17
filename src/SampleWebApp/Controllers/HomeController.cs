using System;
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
        public async Task<ActionResult> Logout()
        {

            bool isAuthenticated = HttpContext.GetOwinContext().Authentication.User.Identity.IsAuthenticated;
            var authenticationResult = await HttpContext.GetOwinContext().Authentication.AuthenticateAsync("keycloak_cookies");
            authenticationResult.Properties.AllowRefresh = false;
            authenticationResult.Properties.ExpiresUtc = DateTimeOffset.UtcNow.Subtract(TimeSpan.FromDays(3));
            authenticationResult.Properties.RedirectUri = Url.Content("~/Home/Index");

            HttpContext.GetOwinContext().Authentication.SignOut(authenticationResult.Properties, "AuthMiddleware", authenticationResult.Identity.AuthenticationType);
           
            return RedirectToAction("Index");
        }

        public void LoggedOut()
        {
            bool isAuthenticated = HttpContext.GetOwinContext().Authentication.User.Identity.IsAuthenticated;
        }
    }
}