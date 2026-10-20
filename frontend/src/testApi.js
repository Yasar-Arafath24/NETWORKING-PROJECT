
import {
  checkBackendConnection,
  getAnalysisHistory,
} from "./services/api";

async function testApi() {
  try {
    await checkBackendConnection();
    console.log("Backend connection: SUCCESS");

    const history = await getAnalysisHistory({
      skip: 0,
      limit: 5,
    });

    console.log("Analysis history:", history);
  } catch (error) {
    console.error("API test failed:", error.message);
  }
}

testApi();
