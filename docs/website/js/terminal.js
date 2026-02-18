(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    var terminal = document.querySelector('.terminal');
    if (!terminal) return;

    var terminalBody = terminal.querySelector('.terminal-body');
    if (!terminalBody) return;

    var scenes = [
      {
        prompt: '> ',
        command: 'Why did pipeline build-api-456 fail in the ci-cd namespace?',
        output: [
          '',
          '  \u25cf Using analyze_failed_pipeline tool...',
          '',
          '  The pipeline build-api-456 failed due to an OOMKilled',
          '  error in the build step \u2014 the container exceeded its',
          '  512Mi memory limit.',
          '',
          '  A secondary issue was an image pull timeout for',
          '  registry.internal/base:latest.',
          '',
          '  Recommended fixes:',
          '    1. Increase memory limit to 1Gi for build-container',
          '    2. Verify registry connectivity and image tag',
          '    3. Add retry policy for transient pull failures',
          '',
          '  Confidence: 94%'
        ]
      },
      {
        prompt: '> ',
        command: 'Are there any resource bottlenecks coming in the production namespace?',
        output: [
          '',
          '  \u25cf Using resource_bottleneck_forecaster tool...',
          '',
          '  Based on current trends, here is the 48\u201372h forecast',
          '  for the production namespace:',
          '',
          '  CPU:     78% projected in 48h     \u26a0 Warning',
          '  Memory:  Critical in 72h          \u2718 Action Required',
          '  Disk:    Stable                   \u2714 OK',
          '',
          '  I recommend:',
          '    1. Scale api-gateway to 4 replicas',
          '    2. Investigate memory leak in payment-service',
          '    3. Lower HPA CPU target from 60% to 50%'
        ]
      },
      {
        prompt: '> ',
        command: 'Map the service topology in the microservices namespace',
        output: [
          '',
          '  \u25cf Using live_system_topology_mapper tool...',
          '',
          '  Discovered 12 services with 3 critical dependency chains.',
          '',
          '  \u26a0 Circular dependency detected:',
          '    order-svc \u2192 inventory-svc \u2192 notification-svc \u2192 order-svc',
          '',
          '  Longest chain (4 hops):',
          '    api-gw \u2192 auth-svc \u2192 user-svc \u2192 db-proxy \u2192 postgres',
          '',
          '  Single points of failure:',
          '    \u2022 auth-svc (9 dependents, no redundancy)',
          '    \u2022 db-proxy (6 dependents, single replica)'
        ]
      }
    ];

    var CHAR_DELAY = 50;
    var POST_COMMAND_PAUSE = 2000;
    var OUTPUT_LINE_DELAY = 300;
    var SCENE_PAUSE = 4000;

    var currentScene = 0;
    var isVisible = true;
    var animationTimer = null;
    var isAnimating = false;

    // Create cursor element
    var cursor = document.createElement('span');
    cursor.className = 'terminal-cursor';
    cursor.textContent = '\u2588';

    // Intersection observer to pause when not visible
    var visibilityObserver = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        isVisible = entry.isIntersecting;
        if (isVisible && !isAnimating) {
          runScene(currentScene);
        }
      });
    }, { threshold: 0.1 });

    visibilityObserver.observe(terminal);

    function clearTerminal() {
      terminalBody.innerHTML = '';
    }

    function createLine() {
      var line = document.createElement('div');
      line.className = 'terminal-line';
      terminalBody.appendChild(line);
      return line;
    }

    function sleep(ms) {
      return new Promise(function (resolve) {
        animationTimer = setTimeout(resolve, ms);
      });
    }

    function typeCommand(line, text, charIndex) {
      return new Promise(function (resolve) {
        function typeNext() {
          if (!isVisible) {
            // Wait and retry when visible
            animationTimer = setTimeout(typeNext, 500);
            return;
          }

          if (charIndex < text.length) {
            line.textContent = text.substring(0, charIndex + 1);
            line.appendChild(cursor);
            charIndex++;
            animationTimer = setTimeout(typeNext, CHAR_DELAY);
          } else {
            resolve();
          }
        }
        typeNext();
      });
    }

    function revealOutputLines(lines) {
      return new Promise(function (resolve) {
        var i = 0;
        function revealNext() {
          if (!isVisible) {
            animationTimer = setTimeout(revealNext, 500);
            return;
          }

          if (i < lines.length) {
            var outputLine = createLine();
            outputLine.className = 'terminal-line terminal-output';
            outputLine.textContent = lines[i];
            i++;

            // Auto-scroll terminal body
            terminalBody.scrollTop = terminalBody.scrollHeight;

            animationTimer = setTimeout(revealNext, OUTPUT_LINE_DELAY);
          } else {
            resolve();
          }
        }
        revealNext();
      });
    }

    async function runScene(index) {
      if (isAnimating) return;
      isAnimating = true;

      var scene = scenes[index];

      clearTerminal();
      var commandLine = createLine();
      commandLine.className = 'terminal-line terminal-command';
      commandLine.textContent = scene.prompt;
      commandLine.appendChild(cursor);

      // Type the command
      await typeCommand(commandLine, scene.prompt + scene.command, scene.prompt.length);

      // Pause after command
      await sleep(POST_COMMAND_PAUSE);

      // Remove cursor from command line
      if (cursor.parentNode === commandLine) {
        commandLine.removeChild(cursor);
      }

      // Reveal output lines
      await revealOutputLines(scene.output);

      // Pause before next scene
      await sleep(SCENE_PAUSE);

      isAnimating = false;

      // Move to next scene
      currentScene = (currentScene + 1) % scenes.length;

      if (isVisible) {
        runScene(currentScene);
      }
    }

    // Start the animation
    if (isVisible) {
      runScene(currentScene);
    }
  });
})();
