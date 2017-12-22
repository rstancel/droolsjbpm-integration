package org.jboss.springboot;

import static org.appformer.maven.integration.MavenRepository.getMavenRepository;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.appformer.maven.integration.MavenRepository;
import org.jbpm.kie.services.impl.KModuleDeploymentUnit;
import org.jbpm.services.api.DeploymentService;
import org.jbpm.services.api.ProcessService;
import org.jbpm.services.api.RuntimeDataService;
import org.jbpm.services.api.UserTaskService;
import org.jbpm.springboot.samples.JBPMApplication;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kie.api.KieServices;
import org.kie.api.builder.ReleaseId;
import org.kie.api.runtime.process.ProcessInstance;
import org.kie.api.task.model.Status;
import org.kie.api.task.model.TaskSummary;
import org.kie.internal.query.QueryFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = {JBPMApplication.class, TestAutoConfiguration.class})
@TestPropertySource(locations="classpath:application-test.properties")
public class BusinessProcessTest {
    
    static final String ARTIFACT_ID = "evaluation";
    static final String GROUP_ID = "org.jbpm.test";
    static final String VERSION = "1.0.0";

    private KModuleDeploymentUnit unit = null;
    
    @Autowired
    private ProcessService processService;
    
    @Autowired
    private DeploymentService deploymentService;
    
    @Autowired
    private UserTaskService userTaskService;
    
    @Autowired
    private RuntimeDataService runtimeDataService;
    
    @BeforeClass
    public static void generalSetup() {
        KieServices ks = KieServices.Factory.get();
        ReleaseId releaseId = ks.newReleaseId(GROUP_ID, ARTIFACT_ID, VERSION);
        File kjar = new File("src/test/resources/kjar/jbpm-module.jar");
        File pom = new File("src/test/resources/kjar/pom.xml");
        MavenRepository repository = getMavenRepository();
        repository.installArtifact(releaseId, kjar, pom);

    }
    
    
    @Before
    public void setup() {
        unit = new KModuleDeploymentUnit(GROUP_ID, ARTIFACT_ID, VERSION);
        deploymentService.deploy(unit);
    }
    
    @After
    public void cleanup() {

        deploymentService.undeploy(unit);
    }
 
    @Test
    public void testProcessStartAndAbort() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("employee", "john");
        parameters.put("reason", "SpringBoot jBPM evaluation");
        long processInstanceId = processService.startProcess(unit.getIdentifier(), "evaluation");
        assertNotNull(processInstanceId);
        assertTrue(processInstanceId > 0);
        
        processService.abortProcessInstance(processInstanceId);
        
        ProcessInstance pi = processService.getProcessInstance(processInstanceId);
        assertNull(pi);
    }
    
    @Test
    public void testProcessStartAndWorkOnUserTasks() {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("employee", "john");
        parameters.put("reason", "SpringBoot jBPM evaluation");
        long processInstanceId = processService.startProcess(unit.getIdentifier(), "evaluation", parameters);
        assertNotNull(processInstanceId);
        assertTrue(processInstanceId > 0);
        
        List<TaskSummary> tasks = runtimeDataService.getTasksAssignedAsPotentialOwner("john", new QueryFilter());
        assertEquals(1, tasks.size());
        
        TaskSummary task = tasks.get(0);
        assertNotNull(task);
        assertEquals("Self Evaluation", task.getName());
        assertEquals(Status.Reserved, task.getStatus());
        
        Map<String, Object> outcome = new HashMap<>();
        
        userTaskService.completeAutoProgress(task.getId(), "john", outcome);
        
        tasks = runtimeDataService.getTasksAssignedAsPotentialOwner("john", new QueryFilter());
        assertEquals(2, tasks.size());
        
        userTaskService.completeAutoProgress(tasks.get(0).getId(), "john", outcome);
        userTaskService.completeAutoProgress(tasks.get(1).getId(), "john", outcome);
        
        ProcessInstance pi = processService.getProcessInstance(processInstanceId);
        assertNull(pi);
    }   
}

