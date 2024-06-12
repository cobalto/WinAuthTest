
using Microsoft.AspNetCore.Authorization;
using System.ServiceModel;

namespace Contracts
{
    [ServiceContract]
    public interface ITestService
    {
        [OperationContract]
        [Authorize(Policy = "WinAuthTestPolicy")]
        void Test();
    }
}
