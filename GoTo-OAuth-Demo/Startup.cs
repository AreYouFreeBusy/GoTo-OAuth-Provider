using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(GoTo_OAuth_Demo.Startup))]
namespace GoTo_OAuth_Demo
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
